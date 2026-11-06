mod detector;
mod remediator;
mod scanner;
mod tester;

use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "\
SecretSentry

Usage:
  secretsentry <directory> [--dry-run]
  secretsentry --self-test
  secretsentry --help

Options:
  --dry-run    Preview secrets and planned code changes without modifying files or writing .env
  --self-test  Run the integrated self-test suite and validation checks
  -h, --help   Print this help message

Scans a directory for secrets, writes them to .env, and rewrites Rust,
Python, and JavaScript/TypeScript string literals into environment calls.
";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
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

    for arg in &args {
        match arg.as_str() {
            "--help" | "-h" => {
                print!("{USAGE}");
                return Ok(());
            }
            "--self-test" => {
                if args.len() > 1 {
                    return Err("unexpected argument with --self-test".into());
                }
                tester::run_self_test()?;
                return Ok(());
            }
            "--dry-run" => {
                dry_run = true;
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

    let Some(path) = target_dir else {
        eprint!("{USAGE}");
        return Err("missing target directory".into());
    };

    run_pipeline(Path::new(path), dry_run)?;
    Ok(())
}

fn run_pipeline(root: &Path, dry_run: bool) -> Result<(), Box<dyn std::error::Error>> {
    let files = scanner::scan(root)?;
    let findings = detector::detect(&files)?;
    println!("scanned {} files", files.len());
    println!("detected {} secrets", findings.len());
    for finding in &findings {
        println!(
            "{}:{}: {} {}",
            finding.path.display(),
            finding.line_number,
            finding.kind,
            finding.value
        );
    }
    let report = remediator::remediate_with_options(root, &findings, dry_run)?;
    if report.dry_run {
        println!();
        println!("[DRY RUN] Planned replacements:");
        for action in &report.planned_actions {
            if let Some(replacement) = &action.replacement {
                println!(
                    "  {}:{}: -> {}",
                    action.path.display(),
                    action.line_number,
                    replacement
                );
            } else {
                println!(
                    "  {}:{}: (cannot rewrite automatically, literal span not isolated)",
                    action.path.display(),
                    action.line_number
                );
            }
        }
        println!();
        println!(
            "[DRY RUN] Would isolate {} keys into {}",
            report.env_keys_written,
            report.env_path.display()
        );
        if report.env_example_keys_written > 0 {
            println!(
                "[DRY RUN] Would create {} with {} placeholder entries",
                report.env_example_path.display(),
                report.env_example_keys_written
            );
        } else {
            println!("[DRY RUN] .env.example already up to date");
        }
        if report.gitignore_updated {
            println!("[DRY RUN] Would add .env to .gitignore");
        } else {
            println!("[DRY RUN] .env already covered in .gitignore");
        }
        println!("[DRY RUN] Would rewrite {} source files", report.files_rewritten);
        println!("[DRY RUN] No files on disk were modified.");
    } else {
        println!(
            "isolated {} keys into {}",
            report.env_keys_written,
            report.env_path.display()
        );
        if report.env_example_keys_written > 0 {
            println!(
                "created {} entries in {}",
                report.env_example_keys_written,
                report.env_example_path.display()
            );
        }
        if report.gitignore_updated {
            println!("added .env to .gitignore");
        }
        println!("rewrote {} source files", report.files_rewritten);
    }
    Ok(())
}
