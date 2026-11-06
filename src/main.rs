mod color;
mod detector;
mod remediator;
mod scanner;
mod tester;

use std::path::Path;
use std::process::ExitCode;

use color::Colors;

const USAGE: &str = "\
SecretSentry

Usage:
  secretsentry <directory> [--dry-run] [--no-color]
  secretsentry --self-test [--no-color]
  secretsentry --help

Options:
  --dry-run    Preview secrets and planned code changes without modifying files or writing .env
  --no-color   Disable ANSI colored terminal output
  --self-test  Run the integrated self-test suite and validation checks
  -h, --help   Print this help message

Scans a directory for secrets, writes them to .env, and rewrites Rust,
Python, and JavaScript/TypeScript string literals into environment calls.
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

    for arg in &args {
        match arg.as_str() {
            "--help" | "-h" => {
                print!("{USAGE}");
                return Ok(());
            }
            "--self-test" => {
                self_test = true;
            }
            "--dry-run" => {
                dry_run = true;
            }
            "--no-color" => {
                no_color = true;
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
    }

    let colors = Colors::new(no_color);

    if self_test {
        if target_dir.is_some() || dry_run {
            return Err("unexpected arguments with --self-test".into());
        }
        tester::run_self_test_with_colors(colors)?;
        return Ok(());
    }

    let Some(path) = target_dir else {
        eprint!("{USAGE}");
        return Err("missing target directory".into());
    };

    run_pipeline(Path::new(path), dry_run, colors)?;
    Ok(())
}

fn run_pipeline(
    root: &Path,
    dry_run: bool,
    colors: Colors,
) -> Result<(), Box<dyn std::error::Error>> {
    let files = scanner::scan(root)?;
    let findings = detector::detect(&files)?;
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
    let report = remediator::remediate_with_options(root, &findings, dry_run)?;
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
