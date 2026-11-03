//! Known secret signatures plus Shannon entropy for unlisted tokens.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use rayon::prelude::*;
use regex::Regex;

static AWS_ACCESS_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:AKIA|ASIA)[0-9A-Z]{16}").expect("AWS access key pattern"));

static OPENAI_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"sk-[A-Za-z0-9]{20,}").expect("OpenAI token pattern"));

const ENTROPY_THRESHOLD: f64 = 4.5;
const MIN_ENTROPY_LEN: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecretKind {
    AwsAccessKey,
    OpenAiToken,
    HighEntropy,
}

impl SecretKind {
    pub fn env_base(self) -> &'static str {
        match self {
            Self::AwsAccessKey => "AWS_ACCESS_KEY_ID",
            Self::OpenAiToken => "OPENAI_API_KEY",
            Self::HighEntropy => "HIGH_ENTROPY_SECRET",
        }
    }
}

impl std::fmt::Display for SecretKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::AwsAccessKey => "AWS access key",
            Self::OpenAiToken => "OpenAI token",
            Self::HighEntropy => "high-entropy string",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub path: PathBuf,
    pub kind: SecretKind,
    pub value: String,
    pub line_number: usize,
    /// Byte span of the surrounding quotes when the secret is the entire literal.
    pub literal_span: Option<(usize, usize)>,
}

#[derive(Debug)]
pub enum DetectError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl std::fmt::Display for DetectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "reading {}: {source}", path.display()),
        }
    }
}

impl std::error::Error for DetectError {}

pub(crate) struct SourceLine<'a> {
    pub number: usize,
    pub text: &'a str,
    pub ending: &'a str,
}

pub(crate) fn source_lines(source: &str) -> Vec<SourceLine<'_>> {
    let mut lines = Vec::new();
    let mut rest = source;
    let mut number = 1usize;
    while let Some(index) = rest.find('\n') {
        let (raw, after) = rest.split_at(index + 1);
        let ending = if raw.ends_with("\r\n") { "\r\n" } else { "\n" };
        let text_len = raw.len() - ending.len();
        lines.push(SourceLine {
            number,
            text: &raw[..text_len],
            ending,
        });
        rest = after;
        number += 1;
    }
    if !rest.is_empty() {
        lines.push(SourceLine {
            number,
            text: rest,
            ending: "",
        });
    }
    lines
}

/// Shannon entropy H(X) = -sum P(x) log2 P(x), measured over bytes.
pub fn shannon_entropy(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for byte in value.bytes() {
        counts[byte as usize] += 1;
    }
    let length = value.len() as f64;
    counts
        .into_iter()
        .filter(|count| *count > 0)
        .map(|count| {
            let probability = count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

/// Detect secrets in `paths`, one file per worker.
pub fn detect(paths: &[PathBuf]) -> Result<Vec<Finding>, DetectError> {
    let mut findings = paths
        .par_iter()
        .map(|path| detect_file(path))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    findings.sort_by(|left, right| {
        (&left.path, left.line_number, &left.value, left.kind).cmp(&(
            &right.path,
            right.line_number,
            &right.value,
            right.kind,
        ))
    });
    Ok(findings)
}

pub fn detect_file(path: &Path) -> Result<Vec<Finding>, DetectError> {
    let bytes = fs::read(path).map_err(|source| DetectError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if bytes.contains(&0) {
        return Ok(Vec::new());
    }
    let Ok(text) = String::from_utf8(bytes) else {
        return Ok(Vec::new());
    };
    Ok(detect_text(path, &text))
}

pub fn detect_text(path: &Path, source: &str) -> Vec<Finding> {
    let style = comment_style(path);
    let mut in_block = false;
    let mut findings = Vec::new();
    for line in source_lines(source) {
        findings.extend(detect_line(
            path,
            line.number,
            line.text,
            style,
            &mut in_block,
        ));
    }
    findings
}

#[derive(Clone, Copy)]
enum CommentStyle {
    Hash,
    Slash,
    None,
}

fn comment_style(path: &Path) -> CommentStyle {
    match path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
        .as_deref()
    {
        Some("py" | "sh" | "bash" | "zsh" | "rb" | "yaml" | "yml" | "toml") => CommentStyle::Hash,
        Some(
            "rs" | "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" | "java" | "go" | "c" | "h" | "cpp",
        ) => CommentStyle::Slash,
        _ => CommentStyle::None,
    }
}

struct Literal {
    quote_span: (usize, usize),
    content_span: (usize, usize),
}

struct LineScan {
    literals: Vec<Literal>,
    comment_ranges: Vec<(usize, usize)>,
}

fn detect_line(
    path: &Path,
    line_number: usize,
    line: &str,
    style: CommentStyle,
    in_block: &mut bool,
) -> Vec<Finding> {
    let scan = scan_line(line, style, in_block);
    let mut findings = Vec::new();

    for (regex, kind) in known_patterns() {
        for matched in regex.find_iter(line) {
            let span = (matched.start(), matched.end());
            let literal_span = if range_in_comment(span.0, &scan.comment_ranges) {
                None
            } else {
                full_literal_span(&scan.literals, span)
            };
            findings.push(Finding {
                path: path.to_path_buf(),
                kind,
                value: matched.as_str().to_string(),
                line_number,
                literal_span,
            });
        }
    }

    for literal in &scan.literals {
        if range_in_comment(literal.content_span.0, &scan.comment_ranges) {
            continue;
        }
        let content = &line[literal.content_span.0..literal.content_span.1];
        if known_patterns()
            .iter()
            .any(|(regex, _)| regex.find(content).is_some())
        {
            continue;
        }
        if is_high_entropy_token(content) {
            findings.push(Finding {
                path: path.to_path_buf(),
                kind: SecretKind::HighEntropy,
                value: content.to_string(),
                line_number,
                literal_span: Some(literal.quote_span),
            });
        }
    }

    findings
}

fn known_patterns() -> [(Regex, SecretKind); 2] {
    [
        (AWS_ACCESS_KEY.clone(), SecretKind::AwsAccessKey),
        (OPENAI_TOKEN.clone(), SecretKind::OpenAiToken),
    ]
}

fn full_literal_span(literals: &[Literal], content_span: (usize, usize)) -> Option<(usize, usize)> {
    literals
        .iter()
        .find_map(|literal| (literal.content_span == content_span).then_some(literal.quote_span))
}

fn range_in_comment(index: usize, comments: &[(usize, usize)]) -> bool {
    comments
        .iter()
        .any(|(start, end)| index >= *start && index < *end)
}

fn is_high_entropy_token(value: &str) -> bool {
    if value.len() < MIN_ENTROPY_LEN {
        return false;
    }
    let token_bytes = value.bytes().all(|byte| {
        matches!(
            byte,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'=' | b'_' | b'-'
        )
    });
    if !token_bytes {
        return false;
    }
    let has_upper = value.bytes().any(|byte| byte.is_ascii_uppercase());
    let has_lower = value.bytes().any(|byte| byte.is_ascii_lowercase());
    let has_digit = value.bytes().any(|byte| byte.is_ascii_digit());
    has_upper && has_lower && has_digit && shannon_entropy(value) >= ENTROPY_THRESHOLD
}

fn scan_line(line: &str, style: CommentStyle, in_block: &mut bool) -> LineScan {
    let bytes = line.as_bytes();
    let mut literals = Vec::new();
    let mut comment_ranges = Vec::new();
    let mut index = 0;
    let mut block_start = if *in_block { Some(0) } else { None };
    let mut line_comment_at = None;

    while index < bytes.len() {
        if *in_block {
            if bytes[index] == b'*' && index + 1 < bytes.len() && bytes[index + 1] == b'/' {
                comment_ranges.push((block_start.unwrap_or(0), index + 2));
                *in_block = false;
                block_start = None;
                index += 2;
                continue;
            }
            index += 1;
            continue;
        }

        if line_comment_at.is_none() {
            if matches!(style, CommentStyle::Hash) && bytes[index] == b'#' {
                line_comment_at = Some(index);
                index += 1;
                continue;
            }
            if matches!(style, CommentStyle::Slash)
                && bytes[index] == b'/'
                && index + 1 < bytes.len()
                && bytes[index + 1] == b'/'
            {
                line_comment_at = Some(index);
                index += 2;
                continue;
            }
            if matches!(style, CommentStyle::Slash)
                && bytes[index] == b'/'
                && index + 1 < bytes.len()
                && bytes[index + 1] == b'*'
            {
                *in_block = true;
                block_start = Some(index);
                index += 2;
                continue;
            }
        }

        if bytes[index] == b'"' || bytes[index] == b'\'' {
            let quote = bytes[index];
            let start = index;
            index += 1;
            let content_start = index;
            let mut closed = false;
            while index < bytes.len() {
                if bytes[index] == b'\\' && index + 1 < bytes.len() {
                    index += 2;
                    continue;
                }
                if bytes[index] == quote {
                    closed = true;
                    break;
                }
                index += 1;
            }
            if !closed {
                break;
            }
            let content_end = index;
            index += 1;
            if line_comment_at.is_none() {
                literals.push(Literal {
                    quote_span: (start, index),
                    content_span: (content_start, content_end),
                });
            }
            continue;
        }

        index += 1;
    }

    if let Some(start) = line_comment_at {
        comment_ranges.push((start, bytes.len()));
    }
    if *in_block {
        comment_ranges.push((block_start.unwrap_or(0), bytes.len()));
    }

    LineScan {
        literals,
        comment_ranges,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_matches_the_shannon_formula() {
        let unique = "q7W9mZ2kP4nR8xL1vC6bH3jF5sD0aYgT";
        assert!((shannon_entropy(unique) - 5.0).abs() < 1e-9);
        assert!(shannon_entropy("AKIAIOSFODNN7EXAMPLE") < ENTROPY_THRESHOLD);
        assert!(!is_high_entropy_token("aaaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(is_high_entropy_token(unique));
    }

    #[test]
    fn classifies_full_literals_and_ignores_comment_spans() {
        let source = "\
# comment = \"AKIAIOSFODNN7EXAMPLE\"
real = \"AKIAIOSFODNN7EXAMPLE\"
partial = \"prefix-AKIAIOSFODNN7EXAMPLE\"
token = \"sk-testOpenAIToken1234567890abcd\"
random = \"q7W9mZ2kP4nR8xL1vC6bH3jF5sD0aYgT\"
";
        let findings = detect_text(Path::new("sample.py"), source);
        let aws: Vec<_> = findings
            .iter()
            .filter(|finding| finding.kind == SecretKind::AwsAccessKey)
            .collect();
        assert_eq!(aws.len(), 3);
        assert_eq!(
            aws.iter()
                .filter(|finding| finding.literal_span.is_some())
                .count(),
            1
        );
        assert!(findings.iter().any(|finding| {
            finding.kind == SecretKind::OpenAiToken && finding.literal_span.is_some()
        }));
        assert!(findings.iter().any(|finding| {
            finding.kind == SecretKind::HighEntropy && finding.literal_span.is_some()
        }));
    }
}
