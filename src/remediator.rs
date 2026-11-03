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
            Self::Overlap { path, line } => {
                write!(f, "overlapping replacements in {}:{}", path.display(), line)
            }
            Self::UnsafeEnvEntry { key } => {
                write!(
                    f,
                    "refusing to write env entry {key} because it contains a newline or '='"
                )
            }
        }
    }
}

impl std::error::Error for RemediateError {}

#[derive(Debug)]
pub struct RemediationReport {
    pub env_path: PathBuf,
    pub env_keys_written: usize,
    pub files_rewritten: usize,
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
    let env_path = root.join(".env");
    if findings.is_empty() {
        return Ok(RemediationReport {
            env_path,
            env_keys_written: 0,
            files_rewritten: 0,
        });
    }

    let planned = plan(findings);
    let mut grouped: BTreeMap<PathBuf, Vec<Planned>> = BTreeMap::new();
    for item in planned {
        grouped.entry(item.path.clone()).or_default().push(item);
    }
    let groups: Vec<(PathBuf, Vec<Planned>)> = grouped.into_iter().collect();

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

    Ok(RemediationReport {
        env_path,
        env_keys_written,
        files_rewritten: rewritten,
    })
}

/// Rewrite `source` the same way file remediation would, without touching disk.
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
}
