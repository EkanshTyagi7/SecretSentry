//! Builds a temporary sandbox, runs the full pipeline, and reports assertions.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::color::Colors;
use crate::detector::{self, SecretKind};
use crate::remediator;
use crate::scanner::{self, ScanOptions};

static SANDBOX_LOCK: Mutex<()> = Mutex::new(());

const AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
const OPENAI_TOKEN: &str = "sk-testOpenAIToken1234567890abcd";
const JWT_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0ODc5MjEwMyIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcwMDAwMDAwMH0.9kL2mxP8vQ1nR4wT7yU0iO3pA5sD7fG9hJ1kL3zX8cV";
const HIGH_ENTROPY: &str = "q7W9mZ2kP4nR8xL1vC6bH3jF5sD0aYgT";
const GCP_SA_KEY: &str = "\"private_key_id\": \"1234567890abcdef1234567890abcdef12345678\"";
const AZURE_CONN: &str = "DefaultEndpointsProtocol=https;AccountName=testacc;AccountKey=SuperSecretKey123+/=;EndpointSuffix=core.windows.net";
const IGNORED_KEY: &str = "AKIAIGNOREDSHOULD001";
const TARGET_KEY: &str = "AKIABUILDDIRSHOULD01";
const NODE_MODULES_KEY: &str = "AKIANODEMODULES00001";

const SANDBOX_DIR: &str = "secret_sentry_test_sandbox";

#[derive(Debug)]
pub struct SelfTestError {
    pub report: String,
}

impl std::fmt::Display for SelfTestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.report)
    }
}

impl std::error::Error for SelfTestError {}

struct Check {
    name: String,
    passed: bool,
    detail: String,
}

struct Sandbox {
    path: PathBuf,
}

impl Sandbox {
    fn create() -> Result<Self, std::io::Error> {
        let path = std::env::current_dir()?.join(SANDBOX_DIR);
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(path.join("target"))?;
        fs::create_dir_all(path.join("node_modules"))?;
        fs::write(path.join(".gitignore"), "ignored_secret.py\n")?;
        fs::write(
            path.join("ignored_secret.py"),
            format!("secret = \"{IGNORED_KEY}\"\n"),
        )?;
        fs::write(
            path.join("target").join("skip.rs"),
            format!("let secret = \"{TARGET_KEY}\";\n"),
        )?;
        fs::write(
            path.join("node_modules").join("left.js"),
            format!("const secret = \"{NODE_MODULES_KEY}\";\n"),
        )?;
        fs::write(path.join("sample.py"), python_source())?;
        fs::write(path.join("sample.js"), javascript_source())?;
        fs::write(path.join("sample.ts"), typescript_source())?;
        fs::write(path.join("sample.rs"), rust_source())?;
        Ok(Self { path })
    }

    fn cleanup(self) -> Result<(), std::io::Error> {
        if self.path.exists() {
            fs::remove_dir_all(&self.path)?;
        }
        Ok(())
    }
}

/// Create `./secret_sentry_test_sandbox/`, run every pipeline, and print assertions.
#[allow(dead_code)]
pub fn run_self_test() -> Result<(), SelfTestError> {
    run_self_test_with_colors(Colors::new(false))
}

/// Run self-test with specific color configuration.
pub fn run_self_test_with_colors(colors: Colors) -> Result<(), SelfTestError> {
    let _lock = SANDBOX_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let sandbox = Sandbox::create().map_err(|err| SelfTestError {
        report: format!("SecretSentry self-test\n  [FAIL] create sandbox: {err}\n"),
    })?;
    let path = sandbox.path.clone();
    let outcome = evaluate(&path, colors);
    let cleanup = sandbox.cleanup();
    match (outcome, cleanup) {
        (Ok(mut checks), Ok(())) => {
            checks.push(Check {
                name: format!("cleaned up ./{}", SANDBOX_DIR),
                passed: true,
                detail: String::new(),
            });
            finish(checks, colors)
        }
        (Ok(mut checks), Err(err)) => {
            checks.push(Check {
                name: format!("cleaned up ./{}", SANDBOX_DIR),
                passed: false,
                detail: err.to_string(),
            });
            finish(checks, colors)
        }
        (Err(err), Ok(())) => Err(err),
        (Err(mut err), Err(cleanup_err)) => {
            err.report.push_str(&format!(
                "  [FAIL] cleanup ./{SANDBOX_DIR}: {cleanup_err}\n"
            ));
            Err(err)
        }
    }
}

fn evaluate(root: &Path, colors: Colors) -> Result<Vec<Check>, SelfTestError> {
    let mut checks = Vec::new();

    let files = match scanner::scan_with(
        root,
        &ScanOptions {
            respect_parent_ignores: false,
            respect_global_gitignore: false,
        },
    ) {
        Ok(files) => files,
        Err(err) => {
            checks.push(Check {
                name: "scanner completed".to_string(),
                passed: false,
                detail: err.to_string(),
            });
            return Err(failure(checks, colors));
        }
    };
    record(
        &mut checks,
        "scanner discovered test files",
        !files.is_empty(),
        "no files returned",
    );

    let (discovered_config, loaded_cfg_path) = match crate::config::Config::find_and_load(root) {
        Ok(res) => res,
        Err(err) => {
            checks.push(Check {
                name: "config loader completed".to_string(),
                passed: false,
                detail: err.to_string(),
            });
            return Err(failure(checks, colors));
        }
    };
    record(
        &mut checks,
        "config loader uses defaults when no file present",
        discovered_config == crate::config::Config::default() && loaded_cfg_path.is_none(),
        "expected default config with no config path",
    );

    let custom_cfg_str = "[ignore]\npatterns = [\"CUSTOM_ALLOWLISTED\"]\nfiles = [\"custom_skip.py\"]\n";
    match crate::config::Config::parse_str(custom_cfg_str, Path::new("dummy.toml")) {
        Ok(parsed) => {
            record(
                &mut checks,
                "config parser reads ignore rules",
                parsed.ignore.patterns == vec!["CUSTOM_ALLOWLISTED"]
                    && parsed.ignore.files == vec!["custom_skip.py"],
                "parsed config did not match expected rules",
            );
        }
        Err(err) => record(&mut checks, "config parser reads ignore rules", false, &err.to_string()),
    }

    let findings = match detector::detect(&files) {
        Ok(findings) => findings,
        Err(err) => {
            checks.push(Check {
                name: "detector completed".to_string(),
                passed: false,
                detail: err.to_string(),
            });
            return Err(failure(checks, colors));
        }
    };
    let dry_run_report = match remediator::remediate_with_options(root, &findings, true) {
        Ok(report) => report,
        Err(err) => {
            checks.push(Check {
                name: "dry run completed".to_string(),
                passed: false,
                detail: err.to_string(),
            });
            return Err(failure(checks, colors));
        }
    };
    record(
        &mut checks,
        "dry run did not create .env",
        !root.join(".env").exists(),
        ".env was created during dry run",
    );
    record(
        &mut checks,
        "dry run did not create .env.example",
        !root.join(".env.example").exists(),
        ".env.example was created during dry run",
    );
    let gitignore_after_dry = fs::read_to_string(root.join(".gitignore")).unwrap_or_default();
    record(
        &mut checks,
        "dry run did not modify .gitignore",
        !gitignore_after_dry.lines().any(|l| l.trim() == ".env"),
        ".gitignore was modified during dry run",
    );
    record(
        &mut checks,
        "dry run predicted rewritten files accurately",
        dry_run_report.files_rewritten == 4,
        &format!("predicted {}", dry_run_report.files_rewritten),
    );
    record(
        &mut checks,
        "dry run predicted env example keys accurately",
        dry_run_report.env_example_keys_written == 6,
        &format!("predicted {}", dry_run_report.env_example_keys_written),
    );
    record(
        &mut checks,
        "dry run predicted gitignore would be updated",
        dry_run_report.gitignore_updated,
        "gitignore_updated should be true",
    );

    let report = match remediator::remediate(root, &findings) {
        Ok(report) => report,
        Err(err) => {
            checks.push(Check {
                name: "remediator completed".to_string(),
                passed: false,
                detail: err.to_string(),
            });
            return Err(failure(checks, colors));
        }
    };

    for name in ["sample.py", "sample.js", "sample.ts", "sample.rs"] {
        record(
            &mut checks,
            &format!("scanner listed {name}"),
            files.iter().any(|path| path.ends_with(name)),
            "",
        );
    }
    record(
        &mut checks,
        "scanner skipped gitignored file",
        files
            .iter()
            .all(|path| !path.ends_with("ignored_secret.py")),
        "",
    );
    record(
        &mut checks,
        "scanner skipped target/",
        files.iter().all(|path| !has_component(path, "target")),
        "",
    );
    record(
        &mut checks,
        "scanner skipped node_modules/",
        files
            .iter()
            .all(|path| !has_component(path, "node_modules")),
        "",
    );

    for name in ["sample.py", "sample.js", "sample.ts", "sample.rs"] {
        record(
            &mut checks,
            &format!("{name} detected the AWS access key"),
            found(&findings, name, SecretKind::AwsAccessKey, AWS_KEY),
            "",
        );
        record(
            &mut checks,
            &format!("{name} detected the OpenAI token"),
            found(&findings, name, SecretKind::OpenAiToken, OPENAI_TOKEN),
            "",
        );
        record(
            &mut checks,
            &format!("{name} detected the high-entropy string"),
            found(&findings, name, SecretKind::HighEntropy, HIGH_ENTROPY),
            "",
        );
    }
    record(
        &mut checks,
        "gitignored secret was not detected",
        findings.iter().all(|finding| finding.value != IGNORED_KEY),
        "",
    );
    record(
        &mut checks,
        "target/ secret was not detected",
        findings.iter().all(|finding| finding.value != TARGET_KEY),
        "",
    );
    record(
        &mut checks,
        "node_modules secret was not detected",
        findings
            .iter()
            .all(|finding| finding.value != NODE_MODULES_KEY),
        "",
    );

    match fs::read_to_string(&report.env_path) {
        Ok(env_file) => {
            let entries: BTreeSet<_> = env_file
                .lines()
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .collect();
            for (key, value) in [
                ("AWS_ACCESS_KEY_ID", AWS_KEY),
                ("OPENAI_API_KEY", OPENAI_TOKEN),
                ("JWT_TOKEN", JWT_TOKEN),
                ("GCP_PRIVATE_KEY_ID", GCP_SA_KEY),
                ("AZURE_STORAGE_CONNECTION_STRING", AZURE_CONN),
                ("HIGH_ENTROPY_SECRET", HIGH_ENTROPY),
            ] {
                let expected = format!("{key}={value}");
                record(
                    &mut checks,
                    &format!(".env contains {key}"),
                    entries.contains(expected.as_str()),
                    &format!("missing {expected}"),
                );
            }
            record(
                &mut checks,
                ".env has one entry per distinct secret",
                entries.len() == 6,
                &format!("found {} entries", entries.len()),
            );
        }
        Err(err) => record(&mut checks, ".env was created", false, &err.to_string()),
    }

    match fs::read_to_string(&report.env_example_path) {
        Ok(content) => {
            let example_entries: BTreeSet<_> = content
                .lines()
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .collect();
            record(
                &mut checks,
                ".env.example has correct number of entries",
                example_entries.len() == 6,
                &format!("found {} entries", example_entries.len()),
            );
            for key in [
                "AWS_ACCESS_KEY_ID",
                "OPENAI_API_KEY",
                "JWT_TOKEN",
                "GCP_PRIVATE_KEY_ID",
                "AZURE_STORAGE_CONNECTION_STRING",
                "HIGH_ENTROPY_SECRET",
            ] {
                let expected = format!("{key}=your_{}_here", key.to_ascii_lowercase());
                record(
                    &mut checks,
                    &format!(".env.example contains {key}"),
                    example_entries.contains(expected.as_str()),
                    &format!("missing: {expected}"),
                );
            }
        }
        Err(err) => record(&mut checks, ".env.example was created", false, &err.to_string()),
    }

    match fs::read_to_string(root.join(".gitignore")) {
        Ok(content) => record(
            &mut checks,
            ".gitignore contains .env",
            content.lines().any(|l| l.trim() == ".env"),
            ".env not found in .gitignore",
        ),
        Err(err) => record(&mut checks, ".gitignore is readable", false, &err.to_string()),
    }

    compare_file(&mut checks, root, "sample.py", &python_expected());
    compare_file(&mut checks, root, "sample.js", &javascript_expected());
    compare_file(&mut checks, root, "sample.ts", &typescript_expected());
    compare_file(&mut checks, root, "sample.rs", &rust_expected());
    compare_file(
        &mut checks,
        root,
        "ignored_secret.py",
        &format!("secret = \"{IGNORED_KEY}\"\n"),
    );
    compare_file(
        &mut checks,
        &root.join("target"),
        "skip.rs",
        &format!("let secret = \"{TARGET_KEY}\";\n"),
    );

    if checks.iter().any(|check| !check.passed) {
        return Err(failure(checks, colors));
    }
    Ok(checks)
}

fn found(findings: &[detector::Finding], file: &str, kind: SecretKind, value: &str) -> bool {
    findings.iter().any(|finding| {
        finding.path.ends_with(file) && finding.kind == kind && finding.value == value
    })
}

fn compare_file(checks: &mut Vec<Check>, dir: &Path, name: &str, expected: &str) {
    match fs::read_to_string(dir.join(name)) {
        Ok(actual) => record(
            checks,
            &format!("{name} rewritten correctly"),
            actual == expected,
            &format!("expected:\n{expected}\nactual:\n{actual}"),
        ),
        Err(err) => record(
            checks,
            &format!("{name} rewritten correctly"),
            false,
            &err.to_string(),
        ),
    }
}

fn has_component(path: &Path, name: &str) -> bool {
    path.components()
        .any(|component| component.as_os_str() == name)
}

fn record(checks: &mut Vec<Check>, name: &str, passed: bool, detail: &str) {
    checks.push(Check {
        name: name.to_string(),
        passed,
        detail: detail.to_string(),
    });
}

fn failure(checks: Vec<Check>, colors: Colors) -> SelfTestError {
    SelfTestError {
        report: render(&checks, colors),
    }
}

fn finish(checks: Vec<Check>, colors: Colors) -> Result<(), SelfTestError> {
    let report = render(&checks, colors);
    println!("{report}");
    if checks.iter().any(|check| !check.passed) {
        Err(SelfTestError { report })
    } else {
        Ok(())
    }
}

fn render(checks: &[Check], colors: Colors) -> String {
    let failed = checks.iter().filter(|check| !check.passed).count();
    let mut report = String::from("SecretSentry self-test\n");
    for check in checks {
        let status = if check.passed {
            colors.bold_green("PASS")
        } else {
            colors.bold_red("FAIL")
        };
        report.push_str(&format!("  [{status}] {}\n", check.name));
        if !check.passed && !check.detail.is_empty() {
            for line in check.detail.lines() {
                report.push_str(&format!("         {}\n", colors.dim(line)));
            }
        }
    }
    let passed_str = if failed == 0 {
        colors.bold_green(&format!("{} passed", checks.len() - failed))
    } else {
        format!("{} passed", checks.len() - failed)
    };
    let failed_str = if failed > 0 {
        colors.bold_red(&format!("{failed} failed"))
    } else {
        format!("{failed} failed")
    };
    report.push_str(&format!("{passed_str}, {failed_str}\n"));
    report
}

fn python_source() -> String {
    format!(
        "\
aws_access_key = \"{AWS_KEY}\"
openai_token = \"{OPENAI_TOKEN}\"
high_entropy = \"{HIGH_ENTROPY}\"
# comment = \"{AWS_KEY}\"
partial = \"prefix-{AWS_KEY}\"
settings = {{
    \"region\": \"us-east-1\",
    \"aws_access_key\": \"{AWS_KEY}\",
}}
"
    )
}

fn python_expected() -> String {
    format!(
        "\
aws_access_key = os.getenv(\"AWS_ACCESS_KEY_ID\")
openai_token = os.getenv(\"OPENAI_API_KEY\")
high_entropy = os.getenv(\"HIGH_ENTROPY_SECRET\")
# comment = \"{AWS_KEY}\"
partial = \"prefix-{AWS_KEY}\"
settings = {{
    \"region\": \"us-east-1\",
    \"aws_access_key\": os.getenv(\"AWS_ACCESS_KEY_ID\"),
}}
"
    )
}

fn javascript_source() -> String {
    format!(
        "\
const awsAccessKey = \"{AWS_KEY}\";
const openaiToken = \"{OPENAI_TOKEN}\";
const jwtToken = \"{JWT_TOKEN}\";
const gcpKey = '{GCP_SA_KEY}';
const azureConn = \"{AZURE_CONN}\";
const highEntropy = \"{HIGH_ENTROPY}\";
"
    )
}

fn javascript_expected() -> String {
    "\
const awsAccessKey = process.env.AWS_ACCESS_KEY_ID;
const openaiToken = process.env.OPENAI_API_KEY;
const jwtToken = process.env.JWT_TOKEN;
const gcpKey = process.env.GCP_PRIVATE_KEY_ID;
const azureConn = process.env.AZURE_STORAGE_CONNECTION_STRING;
const highEntropy = process.env.HIGH_ENTROPY_SECRET;
"
    .to_string()
}

fn typescript_source() -> String {
    format!(
        "\
export const awsAccessKey = \"{AWS_KEY}\";
export const openaiToken = \"{OPENAI_TOKEN}\";
export const highEntropy = \"{HIGH_ENTROPY}\";
"
    )
}

fn typescript_expected() -> String {
    "\
export const awsAccessKey = process.env.AWS_ACCESS_KEY_ID;
export const openaiToken = process.env.OPENAI_API_KEY;
export const highEntropy = process.env.HIGH_ENTROPY_SECRET;
"
    .to_string()
}

fn rust_source() -> String {
    format!(
        "\
fn credentials() {{
    let aws_access_key = \"{AWS_KEY}\";
    let openai_token = \"{OPENAI_TOKEN}\";
    let high_entropy = \"{HIGH_ENTROPY}\";
}}
"
    )
}

fn rust_expected() -> String {
    "\
fn credentials() {
    let aws_access_key = std::env::var(\"AWS_ACCESS_KEY_ID\").unwrap();
    let openai_token = std::env::var(\"OPENAI_API_KEY\").unwrap();
    let high_entropy = std::env::var(\"HIGH_ENTROPY_SECRET\").unwrap();
}
"
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harness_detects_isolates_and_rewrites() {
        run_self_test().unwrap();
    }

    #[test]
    fn harness_runs_with_colors_disabled() {
        run_self_test_with_colors(Colors::new(true)).unwrap();
    }
}
