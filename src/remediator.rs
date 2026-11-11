//! Isolate discovered secrets into `.env` and rewrite supported source literals.
//!
//! Source files are rewritten in parallel. Appends to `.env` share one mutex so
//! concurrent writers cannot interleave lines or drop updates.

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rayon::prelude::*;

use crate::config::Config;
use crate::detector::{self, Finding, SecretKind};

#[derive(Debug)]
pub enum RemediateError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    BadSpan {
        path: PathBuf,
        line: usize,
    },
    Overlap {
        path: PathBuf,
        line: usize,
    },
    UnsafeEnvEntry {
        key: String,
    },
}

impl std::fmt::Display for RemediateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "updating {}: {source}", path.display()),
            Self::BadSpan { path, line } => {
                write!(f, "invalid replacement span in {}:{}", path.display(), line)
            }
            Self::Overlap { path, line } => write!(
                f,
                "conflicting replacements on line {} in {}",
                line,
                path.display()
            ),
            Self::UnsafeEnvEntry { key } => {
                write!(f, "refusing to write malformed .env entry for key '{key}'")
            }
        }
    }
}

impl std::error::Error for RemediateError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedAction {
    pub path: PathBuf,
    pub line_number: usize,
    pub env_key: String,
    pub replacement: Option<String>,
}

#[derive(Debug)]
pub struct RemediationReport {
    pub env_path: PathBuf,
    pub env_keys_written: usize,
    pub files_rewritten: usize,
    pub dry_run: bool,
    pub planned_actions: Vec<PlannedAction>,
    pub env_example_path: PathBuf,
    pub env_example_keys_written: usize,
    pub gitignore_updated: bool,
}

struct Planned {
    path: PathBuf,
    line_number: usize,
    span: Option<(usize, usize)>,
    replacement: Option<String>,
    env_key: String,
    value: String,
}

struct EnvWriter {
    file: File,
    seen: HashSet<String>,
    written: usize,
}

impl EnvWriter {
    fn append(&mut self, key: &str, value: &str) -> Result<bool, RemediateError> {
        if key.contains(['\n', '\r', '=']) || value.contains(['\n', '\r']) {
            return Err(RemediateError::UnsafeEnvEntry {
                key: key.to_string(),
            });
        }
        let line = format!("{key}={value}");
        if !self.seen.insert(line.clone()) {
            return Ok(false);
        }
        self.file
            .write_all(line.as_bytes())
            .and_then(|_| self.file.write_all(b"\n"))
            .map_err(|source| RemediateError::Io {
                path: PathBuf::new(),
                source,
            })?;
        self.written += 1;
        Ok(true)
    }
}

/// Rewrite supported literals and append each distinct secret to `root/.env`.
pub fn remediate(root: &Path, findings: &[Finding]) -> Result<RemediationReport, RemediateError> {
    remediate_with_config(root, findings, false, &Config::default())
}

/// Remediate findings with custom options (such as dry-run).
pub fn remediate_with_options(
    root: &Path,
    findings: &[Finding],
    dry_run: bool,
) -> Result<RemediationReport, RemediateError> {
    remediate_with_config(root, findings, dry_run, &Config::default())
}

/// Remediate findings with full configuration support.
pub fn remediate_with_config(
    root: &Path,
    findings: &[Finding],
    dry_run: bool,
    config: &Config,
) -> Result<RemediationReport, RemediateError> {
    let env_path = root.join(".env");
    let env_example_path = root.join(".env.example");
    let planned = plan(findings);
    let planned_actions: Vec<PlannedAction> = planned
        .iter()
        .map(|item| PlannedAction {
            path: item.path.clone(),
            line_number: item.line_number,
            env_key: item.env_key.clone(),
            replacement: item.replacement.clone(),
        })
        .collect();

    let mut seen_keys: HashSet<String> = HashSet::new();
    let mut unique_env_keys: Vec<String> = Vec::new();
    for item in &planned {
        if seen_keys.insert(item.env_key.clone()) {
            unique_env_keys.push(item.env_key.clone());
        }
    }

    if findings.is_empty() {
        return Ok(RemediationReport {
            env_path,
            env_keys_written: 0,
            files_rewritten: 0,
            dry_run,
            planned_actions,
            env_example_path,
            env_example_keys_written: 0,
            gitignore_updated: false,
        });
    }

    let mut grouped: BTreeMap<PathBuf, Vec<Planned>> = BTreeMap::new();
    for item in planned {
        grouped.entry(item.path.clone()).or_default().push(item);
    }
    let groups: Vec<(PathBuf, Vec<Planned>)> = grouped.into_iter().collect();

    if dry_run {
        let seen: HashSet<String> = if env_path.exists() {
            fs::read_to_string(&env_path)
                .map_err(|source| RemediateError::Io {
                    path: env_path.clone(),
                    source,
                })?
                .lines()
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .map(str::to_string)
                .collect()
        } else {
            HashSet::new()
        };

        let mut already_seen = seen;
        let mut would_write_keys = 0;
        for action in &planned_actions {
            if action.env_key.contains(['\n', '\r', '=']) {
                return Err(RemediateError::UnsafeEnvEntry {
                    key: action.env_key.clone(),
                });
            }
            if let Some(finding) = findings
                .iter()
                .find(|f| f.path == action.path && f.line_number == action.line_number)
            {
                if finding.value.contains(['\n', '\r']) {
                    return Err(RemediateError::UnsafeEnvEntry {
                        key: action.env_key.clone(),
                    });
                }
                let entry = format!("{}={}", action.env_key, finding.value);
                if already_seen.insert(entry) {
                    would_write_keys += 1;
                }
            }
        }

        let mut files_to_rewrite = 0;
        for (path, edits) in &groups {
            if edits.iter().any(|edit| edit.replacement.is_some()) {
                let source = fs::read_to_string(path).map_err(|source| RemediateError::Io {
                    path: path.to_path_buf(),
                    source,
                })?;
                let updated = apply_edits(path, &source, edits)?;
                if updated != source {
                    files_to_rewrite += 1;
                }
            }
        }

        let env_example_keys_written = if config.remediator.create_env_example {
            write_env_example(&env_example_path, &unique_env_keys, true)?
        } else {
            0
        };
        let gitignore_updated = if config.remediator.update_gitignore {
            ensure_gitignore_has_env(root, true)?
        } else {
            false
        };

        return Ok(RemediationReport {
            env_path,
            env_keys_written: would_write_keys,
            files_rewritten: files_to_rewrite,
            dry_run: true,
            planned_actions,
            env_example_path,
            env_example_keys_written,
            gitignore_updated,
        });
    }

    let writer = Mutex::new(open_env(&env_path)?);
    let rewritten = groups
        .par_iter()
        .map(|(path, edits)| apply_group(path, edits, &env_path, &writer))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|changed| *changed)
        .count();

    let env_keys_written = writer
        .into_inner()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .written;

    let env_example_keys_written = if config.remediator.create_env_example {
        write_env_example(&env_example_path, &unique_env_keys, false)?
    } else {
        0
    };
    let gitignore_updated = if config.remediator.update_gitignore {
        ensure_gitignore_has_env(root, false)?
    } else {
        false
    };

    Ok(RemediationReport {
        env_path,
        env_keys_written,
        files_rewritten: rewritten,
        dry_run: false,
        planned_actions,
        env_example_path,
        env_example_keys_written,
        gitignore_updated,
    })
}

/// Rewrite `source` the same way file remediation would, without touching disk.
#[allow(dead_code)]
pub fn rewrite_text(
    path: &Path,
    source: &str,
    findings: &[Finding],
) -> Result<String, RemediateError> {
    let edits: Vec<Planned> = plan(findings)
        .into_iter()
        .filter(|edit| edit.path == path)
        .collect();
    apply_edits(path, source, &edits)
}

fn plan(findings: &[Finding]) -> Vec<Planned> {
    let mut ordered = findings.to_vec();
    ordered.sort_by(|left, right| {
        (left.kind, &left.value, &left.path, left.line_number).cmp(&(
            right.kind,
            &right.value,
            &right.path,
            right.line_number,
        ))
    });

    let mut next_index: BTreeMap<SecretKind, usize> = BTreeMap::new();
    let mut key_for_value: BTreeMap<(SecretKind, String), String> = BTreeMap::new();
    let mut planned = Vec::with_capacity(ordered.len());

    for finding in ordered {
        let env_key = key_for_value
            .entry((finding.kind, finding.value.clone()))
            .or_insert_with(|| assign_key(finding.kind, &mut next_index))
            .clone();
        let replacement = finding.literal_span.and_then(|_| {
            extension_of(&finding.path).and_then(|ext| env_expression(&ext, &env_key))
        });
        planned.push(Planned {
            path: finding.path,
            line_number: finding.line_number,
            span: finding.literal_span.filter(|_| replacement.is_some()),
            replacement,
            env_key,
            value: finding.value,
        });
    }
    planned
}

fn assign_key(kind: SecretKind, next_index: &mut BTreeMap<SecretKind, usize>) -> String {
    let index = next_index.entry(kind).or_insert(0);
    let key = if *index == 0 {
        kind.env_base().to_string()
    } else {
        format!("{}_{}", kind.env_base(), *index + 1)
    };
    *index += 1;
    key
}

fn extension_of(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
}

fn env_expression(extension: &str, key: &str) -> Option<String> {
    match extension {
        "rs" => Some(format!("std::env::var(\"{key}\").unwrap()")),
        "py" => Some(format!("os.getenv(\"{key}\")")),
        "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" => Some(format!("process.env.{key}")),
        _ => None,
    }
}

fn open_env(path: &Path) -> Result<EnvWriter, RemediateError> {
    let seen = if path.exists() {
        fs::read_to_string(path)
            .map_err(|source| RemediateError::Io {
                path: path.to_path_buf(),
                source,
            })?
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(str::to_string)
            .collect()
    } else {
        HashSet::new()
    };
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|source| RemediateError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if seen.is_empty() && file.metadata().map(|meta| meta.len()).unwrap_or(0) == 0 {
        file.write_all(b"# Isolated by SecretSentry\n")
            .map_err(|source| RemediateError::Io {
                path: path.to_path_buf(),
                source,
            })?;
    }
    Ok(EnvWriter {
        file,
        seen,
        written: 0,
    })
}

fn placeholder_for(key: &str) -> String {
    format!("your_{}_here", key.to_ascii_lowercase())
}

fn write_env_example(
    path: &Path,
    unique_env_keys: &[String],
    dry_run: bool,
) -> Result<usize, RemediateError> {
    let (existing_keys, file_already_existed, needs_leading_newline) = if path.exists() {
        let content = fs::read_to_string(path)
            .map_err(|source| RemediateError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        let keys: HashSet<String> = content
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.starts_with('#') || line.is_empty() {
                    return None;
                }
                line.split_once('=').map(|(k, _)| k.trim().to_string())
            })
            .collect();
        let needs_nl = !content.is_empty() && !content.ends_with('\n');
        (keys, true, needs_nl)
    } else {
        (HashSet::new(), false, false)
    };

    let new_keys: Vec<&String> = unique_env_keys
        .iter()
        .filter(|key| !existing_keys.contains(*key))
        .collect();

    if dry_run {
        return Ok(new_keys.len());
    }
    if new_keys.is_empty() {
        return Ok(0);
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|source| RemediateError::Io {
            path: path.to_path_buf(),
            source,
        })?;

    if !file_already_existed {
        file.write_all(b"# .env.example - Generated by SecretSentry\n")
            .and_then(|_| {
                file.write_all(b"# Copy this file to .env and fill in your actual credentials\n")
            })
            .map_err(|source| RemediateError::Io {
                path: path.to_path_buf(),
                source,
            })?;
    } else if needs_leading_newline {
        file.write_all(b"\n")
            .map_err(|source| RemediateError::Io {
                path: path.to_path_buf(),
                source,
            })?;
    }

    for key in &new_keys {
        let line = format!("{}={}\n", key, placeholder_for(key));
        file.write_all(line.as_bytes())
            .map_err(|source| RemediateError::Io {
                path: path.to_path_buf(),
                source,
            })?;
    }
    Ok(new_keys.len())
}

fn ensure_gitignore_has_env(root: &Path, dry_run: bool) -> Result<bool, RemediateError> {
    let gitignore_path = root.join(".gitignore");
    let (already_covered, is_empty, needs_leading_newline) = if gitignore_path.exists() {
        let content = fs::read_to_string(&gitignore_path)
            .map_err(|source| RemediateError::Io {
                path: gitignore_path.clone(),
                source,
            })?;
        let covered = content.lines().any(|line| {
            let t = line.trim();
            !t.starts_with('#') && matches!(t, ".env" | ".env*" | "*.env" | "**/.env")
        });
        let empty = content.trim().is_empty();
        let needs_nl = !content.is_empty() && !content.ends_with('\n');
        (covered, empty, needs_nl)
    } else {
        (false, true, false)
    };

    if already_covered {
        return Ok(false);
    }
    if dry_run {
        return Ok(true);
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&gitignore_path)
        .map_err(|source| RemediateError::Io {
            path: gitignore_path.clone(),
            source,
        })?;

    let to_write = if is_empty {
        "# Added by SecretSentry - keep secrets out of version control\n.env\n"
    } else if needs_leading_newline {
        "\n\n# Added by SecretSentry - keep secrets out of version control\n.env\n"
    } else {
        "\n# Added by SecretSentry - keep secrets out of version control\n.env\n"
    };

    file.write_all(to_write.as_bytes())
        .map_err(|source| RemediateError::Io {
            path: gitignore_path,
            source,
        })?;
    Ok(true)
}

fn apply_group(
    path: &Path,
    edits: &[Planned],
    env_path: &Path,
    writer: &Mutex<EnvWriter>,
) -> Result<bool, RemediateError> {
    let changed = if edits.iter().any(|edit| edit.replacement.is_some()) {
        let source = fs::read_to_string(path).map_err(|source| RemediateError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let updated = apply_edits(path, &source, edits)?;
        if updated != source {
            atomic_write(path, &updated)?;
            true
        } else {
            false
        }
    } else {
        false
    };

    let mut guard = writer
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for edit in edits {
        guard
            .append(&edit.env_key, &edit.value)
            .map_err(|err| match err {
                RemediateError::Io { source, .. } => RemediateError::Io {
                    path: env_path.to_path_buf(),
                    source,
                },
                other => other,
            })?;
    }
    Ok(changed)
}

fn apply_edits(path: &Path, source: &str, edits: &[Planned]) -> Result<String, RemediateError> {
    let mut by_line: BTreeMap<usize, Vec<&Planned>> = BTreeMap::new();
    for edit in edits {
        if edit.span.is_some() {
            by_line.entry(edit.line_number).or_default().push(edit);
        }
    }

    let mut output = String::with_capacity(source.len());
    for line in detector::source_lines(source) {
        if let Some(edits) = by_line.get(&line.number) {
            output.push_str(&replace_spans(path, line.number, line.text, edits)?);
        } else {
            output.push_str(line.text);
        }
        output.push_str(line.ending);
    }
    Ok(output)
}

fn replace_spans(
    path: &Path,
    line_number: usize,
    text: &str,
    edits: &[&Planned],
) -> Result<String, RemediateError> {
    let mut ordered = edits.to_vec();
    ordered.sort_by_key(|edit| edit.span.map(|(start, _)| start).unwrap_or(0));

    let mut output = String::with_capacity(text.len());
    let mut cursor = 0usize;
    for edit in ordered {
        let Some((start, end)) = edit.span else {
            continue;
        };
        let Some(replacement) = edit.replacement.as_deref() else {
            continue;
        };
        if start < cursor
            || end > text.len()
            || !text.is_char_boundary(start)
            || !text.is_char_boundary(end)
        {
            return Err(if start < cursor {
                RemediateError::Overlap {
                    path: path.to_path_buf(),
                    line: line_number,
                }
            } else {
                RemediateError::BadSpan {
                    path: path.to_path_buf(),
                    line: line_number,
                }
            });
        }
        output.push_str(&text[cursor..start]);
        output.push_str(replacement);
        cursor = end;
    }
    output.push_str(&text[cursor..]);
    Ok(output)
}

fn atomic_write(path: &Path, contents: &str) -> Result<(), RemediateError> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("file");
    let tmp = path.with_file_name(format!(".{file_name}.secretsentry.tmp"));
    fs::write(&tmp, contents).map_err(|source| RemediateError::Io {
        path: tmp.clone(),
        source,
    })?;
    fs::rename(&tmp, path).map_err(|source| {
        let _ = fs::remove_file(&tmp);
        RemediateError::Io {
            path: path.to_path_buf(),
            source,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::detect_text;

    #[test]
    fn language_calls_match_the_file_extension() {
        assert_eq!(
            env_expression("rs", "AWS_ACCESS_KEY_ID").as_deref(),
            Some("std::env::var(\"AWS_ACCESS_KEY_ID\").unwrap()")
        );
        assert_eq!(
            env_expression("py", "OPENAI_API_KEY").as_deref(),
            Some("os.getenv(\"OPENAI_API_KEY\")")
        );
        assert_eq!(
            env_expression("js", "HIGH_ENTROPY_SECRET").as_deref(),
            Some("process.env.HIGH_ENTROPY_SECRET")
        );
        assert_eq!(
            env_expression("ts", "HIGH_ENTROPY_SECRET").as_deref(),
            Some("process.env.HIGH_ENTROPY_SECRET")
        );
        assert_eq!(env_expression("go", "AWS_ACCESS_KEY_ID"), None);
    }

    #[test]
    fn preserves_comments_partial_strings_and_surrounding_code() {
        let path = Path::new("sample.py");
        let source = "\
# comment = \"AKIAIOSFODNN7EXAMPLE\"
real = \"AKIAIOSFODNN7EXAMPLE\"
partial = \"prefix-AKIAIOSFODNN7EXAMPLE\"
settings = {
    \"region\": \"us-east-1\",
    \"aws_access_key\": \"AKIAIOSFODNN7EXAMPLE\",
}
";
        let findings = detect_text(path, source);
        let rewritten = rewrite_text(path, source, &findings).unwrap();
        assert_eq!(
            rewritten,
            "\
# comment = \"AKIAIOSFODNN7EXAMPLE\"
real = os.getenv(\"AWS_ACCESS_KEY_ID\")
partial = \"prefix-AKIAIOSFODNN7EXAMPLE\"
settings = {
    \"region\": \"us-east-1\",
    \"aws_access_key\": os.getenv(\"AWS_ACCESS_KEY_ID\"),
}
"
        );
    }

    #[test]
    fn dry_run_does_not_modify_disk() {
        let temp_dir = std::env::temp_dir().join("secretsentry_dry_run_test");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();
        let file_path = temp_dir.join("sample.py");
        let original_content = "aws_key = \"AKIAIOSFODNN7EXAMPLE\"\n";
        fs::write(&file_path, original_content).unwrap();

        let findings = detect_text(&file_path, original_content);
        let report = remediate_with_options(&temp_dir, &findings, true).unwrap();

        assert!(report.dry_run);
        assert_eq!(report.files_rewritten, 1);
        assert_eq!(report.env_keys_written, 1);
        assert!(!temp_dir.join(".env").exists(), ".env must not exist after dry run");
        assert_eq!(
            fs::read_to_string(&file_path).unwrap(),
            original_content,
            "file content must remain unchanged"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn dry_run_does_not_create_env_example_or_modify_gitignore() {
        let temp_dir = std::env::temp_dir().join("secretsentry_envexample_dry_test");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();
        fs::write(temp_dir.join(".gitignore"), "ignored.txt\n").unwrap();
        let file_path = temp_dir.join("sample.py");
        let content = "aws_key = \"AKIAIOSFODNN7EXAMPLE\"\n";
        fs::write(&file_path, content).unwrap();

        let findings = detect_text(&file_path, content);
        let report = remediate_with_options(&temp_dir, &findings, true).unwrap();
        assert!(report.dry_run);
        assert!(!temp_dir.join(".env").exists());
        assert!(!temp_dir.join(".env.example").exists());
        assert_eq!(report.env_example_keys_written, 1);
        assert!(report.gitignore_updated);
        let gitignore = fs::read_to_string(temp_dir.join(".gitignore")).unwrap();
        assert!(!gitignore.contains(".env"), ".gitignore must not be modified in dry-run");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn live_run_creates_env_example_and_updates_gitignore() {
        let temp_dir = std::env::temp_dir().join("secretsentry_live_envexample_test");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();
        fs::write(temp_dir.join(".gitignore"), "ignored.txt\n").unwrap();
        let file_path = temp_dir.join("sample.py");
        let content = "aws_key = \"AKIAIOSFODNN7EXAMPLE\"\n";
        fs::write(&file_path, content).unwrap();

        let findings = detect_text(&file_path, content);
        let report = remediate_with_options(&temp_dir, &findings, false).unwrap();
        assert!(!report.dry_run);
        assert_eq!(report.env_example_keys_written, 1);
        assert!(report.gitignore_updated);

        let example = fs::read_to_string(temp_dir.join(".env.example")).unwrap();
        assert!(example.contains("AWS_ACCESS_KEY_ID=your_aws_access_key_id_here"));

        let gitignore = fs::read_to_string(temp_dir.join(".gitignore")).unwrap();
        assert!(gitignore.lines().any(|l| l.trim() == ".env"));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn config_disables_env_example_and_gitignore() {
        let mut config = Config::default();
        config.remediator.create_env_example = false;
        config.remediator.update_gitignore = false;

        let temp_dir = std::env::temp_dir().join("secretsentry_cfg_remediator_test");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();
        let file_path = temp_dir.join("sample.py");
        let content = "aws_key = \"AKIAIOSFODNN7EXAMPLE\"\n";
        fs::write(&file_path, content).unwrap();

        let findings = detect_text(&file_path, content);
        let report = remediate_with_config(&temp_dir, &findings, false, &config).unwrap();

        assert_eq!(report.env_example_keys_written, 0);
        assert!(!report.gitignore_updated);
        assert!(!temp_dir.join(".env.example").exists());
        assert!(!temp_dir.join(".gitignore").exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
