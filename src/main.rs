mod color;
mod config;
mod detector;
mod hook;
mod remediator;
mod scanner;
mod tester;

use std::path::Path;
use std::process::ExitCode;

use color::Colors;
use config::Config;

const USAGE: &str = "\
SecretSentry

Usage:
  secretsentry <directory> [--dry-run] [--no-color] [--config <path>]
  secretsentry --install-hook [directory] [--no-color]
  secretsentry --self-test [--no-color]
  secretsentry --help

Options:
  --dry-run        Preview secrets and planned code changes without modifying files or writing .env
  --no-color       Disable ANSI colored terminal output
  --config <path>  Path to configuration file (default: <directory>/.secretsentry.toml)
  --install-hook   Install Git pre-commit hook to block commits containing secrets
  --self-test      Run the integrated self-test suite and validation checks
  -h, --help       Print this help message

Scans a directory for secrets, writes them to .env, and rewrites Rust,
Python, JavaScript/TypeScript, Go, Java, C#, PHP, and Ruby literals into environment calls.
";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let colors = Colors::new(false);
            eprintln!("{} {err}", colors.bold_red("error:"));
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprint!("{USAGE}");
        return Err("missing target directory".into());
    }

    let mut target_dir: Option<&str> = None;
    let mut dry_run = false;
    let mut no_color = false;
    let mut self_test = false;
    let mut install_hook = false;
    let mut config_path: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print!("{USAGE}");
                return Ok(());
            }
            "--self-test" => {
                self_test = true;
            }
            "--install-hook" => {
                install_hook = true;
            }
            "--dry-run" => {
                dry_run = true;
            }
            "--no-color" => {
                no_color = true;
            }
            "--config" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing path argument after --config".into());
                }
                config_path = Some(args[i].clone());
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown option '{other}'").into());
            }
            path => {
                if target_dir.is_some() {
                    return Err("too many arguments: please specify only one directory".into());
                }
                target_dir = Some(path);
            }
        }
        i += 1;
    }

    let colors = Colors::new(no_color);

    if self_test {
        if target_dir.is_some() || dry_run || config_path.is_some() || install_hook {
            return Err("unexpected arguments with --self-test".into());
        }
        tester::run_self_test_with_colors(colors)?;
        return Ok(());
    }

    if install_hook {
        if dry_run || config_path.is_some() {
            return Err("unexpected arguments with --install-hook".into());
        }
        let target_path = Path::new(target_dir.unwrap_or("."));
        let status = hook::install_hook(target_path)?;
        hook::print_install_result(target_path, status, &colors);
        return Ok(());
    }

    let Some(path_str) = target_dir else {
        eprint!("{USAGE}");
        return Err("missing target directory".into());
    };
    let path = Path::new(path_str);

    let (config, loaded_from) = if let Some(ref custom_cfg) = config_path {
        let p = Path::new(custom_cfg);
        (Config::load_from_file(p)?, Some(p.to_path_buf()))
    } else {
        Config::find_and_load(path)?
    };

    run_pipeline(path, dry_run, colors, &config, loaded_from.as_deref())?;
    Ok(())
}

fn run_pipeline(
    root: &Path,
    dry_run: bool,
    colors: Colors,
    config: &Config,
    loaded_from: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(cfg_path) = loaded_from {
        println!(
            "{} {}",
            colors.dim("loaded configuration from"),
            colors.cyan(&cfg_path.display().to_string())
        );
    }
    let files = scanner::scan_with_config(root, &scanner::ScanOptions::default(), config)?;
    let findings = detector::detect_with_config(&files, config)?;
    println!(
        "{} {}",
        colors.cyan("scanned"),
        format!("{} files", files.len())
    );
    if findings.is_empty() {
        println!("{}", colors.bold_green("detected 0 secrets"));
    } else {
        println!(
            "{}",
            colors.bold_yellow(&format!("detected {} secrets", findings.len()))
        );
    }
    for finding in &findings {
        println!(
            "{}:{}: {} {}",
            colors.bold(&finding.path.display().to_string()),
            colors.cyan(&finding.line_number.to_string()),
            colors.bold_red(&finding.kind.to_string()),
            colors.red(&finding.value)
        );
    }
    let report = remediator::remediate_with_config(root, &findings, dry_run, config)?;
    if report.dry_run {
        println!();
        println!(
            "{} {}",
            colors.bold_yellow("[DRY RUN]"),
            colors.bold("Planned replacements:")
        );
        for action in &report.planned_actions {
            if let Some(replacement) = &action.replacement {
                println!(
                    "  {}:{}: -> {}",
                    action.path.display(),
                    action.line_number,
                    colors.bold_green(replacement)
                );
            } else {
                println!(
                    "  {}:{}: {}",
                    action.path.display(),
                    action.line_number,
                    colors.dim("(cannot rewrite automatically, literal span not isolated)")
                );
            }
        }
        println!();
        println!(
            "{} Would isolate {} keys into {}",
            colors.bold_yellow("[DRY RUN]"),
            colors.bold(&report.env_keys_written.to_string()),
            colors.cyan(&report.env_path.display().to_string())
        );
        if report.env_example_keys_written > 0 {
            println!(
                "{} Would create {} with {} placeholder entries",
                colors.bold_yellow("[DRY RUN]"),
                colors.cyan(&report.env_example_path.display().to_string()),
                colors.bold(&report.env_example_keys_written.to_string())
            );
        } else {
            println!(
                "{} .env.example already up to date",
                colors.bold_yellow("[DRY RUN]")
            );
        }
        if report.gitignore_updated {
            println!(
                "{} Would add .env to .gitignore",
                colors.bold_yellow("[DRY RUN]")
            );
        } else {
            println!(
                "{} .env already covered in .gitignore",
                colors.bold_yellow("[DRY RUN]")
            );
        }
        println!(
            "{} Would rewrite {} source files",
            colors.bold_yellow("[DRY RUN]"),
            colors.bold(&report.files_rewritten.to_string())
        );
        println!(
            "{} {}",
            colors.bold_yellow("[DRY RUN]"),
            colors.dim("No files on disk were modified.")
        );
    } else {
        println!(
            "{} {} keys into {}",
            colors.bold_green("isolated"),
            colors.bold(&report.env_keys_written.to_string()),
            colors.cyan(&report.env_path.display().to_string())
        );
        if report.env_example_keys_written > 0 {
            println!(
                "{} {} entries in {}",
                colors.bold_green("created"),
                colors.bold(&report.env_example_keys_written.to_string()),
                colors.cyan(&report.env_example_path.display().to_string())
            );
        }
        if report.gitignore_updated {
            println!("{}", colors.bold_green("added .env to .gitignore"));
        }
        println!(
            "{} {} source files",
            colors.bold_green("rewrote"),
            colors.bold(&report.files_rewritten.to_string())
        );
    }
    Ok(())
}
