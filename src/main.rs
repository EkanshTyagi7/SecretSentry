mod detector;
mod remediator;
mod scanner;
mod tester;

use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "\
SecretSentry

Usage:
  secretsentry <directory>
  secretsentry --self-test

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
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("--help" | "-h") => {
            print!("{USAGE}");
            Ok(())
        }
        Some("--self-test") => {
            if args.next().is_some() {
                return Err("unexpected argument after --self-test".into());
            }
            tester::run_self_test()?;
            Ok(())
        }
        Some(path) => {
            if args.next().is_some() {
                return Err("too many arguments".into());
            }
            run_pipeline(Path::new(path))?;
            Ok(())
        }
        None => {
            eprint!("{USAGE}");
            Err("missing target directory".into())
        }
    }
}

fn run_pipeline(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
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
    let report = remediator::remediate(root, &findings)?;
    println!(
        "isolated {} keys into {}",
        report.env_keys_written,
        report.env_path.display()
    );
    println!("rewrote {} source files", report.files_rewritten);
    Ok(())
}
