//! Known secret signatures plus Shannon entropy for unlisted tokens.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use rayon::prelude::*;
use regex::Regex;

use crate::config::Config;

// ── Existing patterns ────────────────────────────────────────────────────────

static AWS_ACCESS_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:AKIA|ASIA)[0-9A-Z]{16}").expect("AWS access key pattern"));

static OPENAI_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"sk-[A-Za-z0-9]{20,}").expect("OpenAI token pattern"));

static JWT_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+")
        .expect("JWT token pattern")
});

static GCP_SERVICE_ACCOUNT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""private_key_id":\s*"[0-9a-f]{40}""#).expect("GCP service account pattern")
});

static AZURE_STORAGE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"DefaultEndpointsProtocol=https;AccountName=[a-z0-9]+;AccountKey=[A-Za-z0-9+/=]+;EndpointSuffix=core\.windows\.net")
        .expect("Azure storage pattern")
});

// ── Step 2: new provider patterns ────────────────────────────────────────────

/// GitHub classic PATs:   ghp_<36 alphanumeric>
/// GitHub fine-grained:   github_pat_<82 alphanumeric+underscore>
static GITHUB_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})")
        .expect("GitHub token pattern")
});

/// Slack bot / user / app / legacy-bot tokens: xoxb-…, xoxp-…, xoxa-…, xoxr-…, xoxs-…
/// Real tokens contain multiple dash-separated segments, e.g. xoxb-123-456-abc
static SLACK_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"xox[baprs]-[0-9A-Za-z-]{10,100}").expect("Slack token pattern")
});

/// Slack incoming-webhook URLs
static SLACK_WEBHOOK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+")
        .expect("Slack webhook pattern")
});

/// Stripe live secret keys:      sk_live_<24+ alphanumeric>
/// Stripe live restricted keys:  rk_live_<24+ alphanumeric>
static STRIPE_SECRET_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:sk|rk)_live_[0-9A-Za-z]{24,}").expect("Stripe secret key pattern")
});

/// Google Cloud / Maps / Firebase API keys: AIza<35 base64url chars>
static GOOGLE_API_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"AIza[0-9A-Za-z\-_]{35}").expect("Google API key pattern")
});

// ────────────────────────────────────────────────────────────────────────────

#[allow(dead_code)]
const ENTROPY_THRESHOLD: f64 = 4.5;
#[allow(dead_code)]
const MIN_ENTROPY_LEN: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecretKind {
    AwsAccessKey,
    OpenAiToken,
    JwtToken,
    GcpServiceAccount,
    AzureStorage,
    // Step 2 additions
    GitHubToken,
    SlackToken,
    SlackWebhook,
    StripeSecretKey,
    GoogleApiKey,
    // Always last — catch-all
    HighEntropy,
}

impl SecretKind {
    pub fn env_base(self) -> &'static str {
        match self {
            Self::AwsAccessKey      => "AWS_ACCESS_KEY_ID",
            Self::OpenAiToken       => "OPENAI_API_KEY",
            Self::JwtToken          => "JWT_TOKEN",
            Self::GcpServiceAccount => "GCP_PRIVATE_KEY_ID",
            Self::AzureStorage      => "AZURE_STORAGE_CONNECTION_STRING",
            Self::GitHubToken       => "GITHUB_TOKEN",
            Self::SlackToken        => "SLACK_TOKEN",
            Self::SlackWebhook      => "SLACK_WEBHOOK_URL",
            Self::StripeSecretKey   => "STRIPE_SECRET_KEY",
            Self::GoogleApiKey      => "GOOGLE_API_KEY",
            Self::HighEntropy       => "HIGH_ENTROPY_SECRET",
        }
    }
}

impl std::fmt::Display for SecretKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::AwsAccessKey      => "AWS access key",
            Self::OpenAiToken       => "OpenAI token",
            Self::JwtToken          => "JWT token",
            Self::GcpServiceAccount => "GCP service account key ID",
            Self::AzureStorage      => "Azure storage connection string",
            Self::GitHubToken       => "GitHub token",
            Self::SlackToken        => "Slack token",
            Self::SlackWebhook      => "Slack webhook URL",
            Self::StripeSecretKey   => "Stripe secret key",
            Self::GoogleApiKey      => "Google API key",
            Self::HighEntropy       => "high-entropy string",
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

/// Detect secrets in `paths`, one file per worker, using default config.
pub fn detect(paths: &[PathBuf]) -> Result<Vec<Finding>, DetectError> {
    detect_with_config(paths, &Config::default())
}

/// Detect secrets in `paths`, one file per worker, honoring `config`.
pub fn detect_with_config(paths: &[PathBuf], config: &Config) -> Result<Vec<Finding>, DetectError> {
    let mut findings = paths
        .par_iter()
        .map(|path| detect_file_with_config(path, config))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .filter(|finding| !config.is_secret_ignored(&finding.value))
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

#[allow(dead_code)]
pub fn detect_file(path: &Path) -> Result<Vec<Finding>, DetectError> {
    detect_file_with_config(path, &Config::default())
}

pub fn detect_file_with_config(path: &Path, config: &Config) -> Result<Vec<Finding>, DetectError> {
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
    Ok(detect_text_with_config(path, &text, config))
}

#[allow(dead_code)]
pub fn detect_text(path: &Path, source: &str) -> Vec<Finding> {
    detect_text_with_config(path, source, &Config::default())
}

pub fn detect_text_with_config(path: &Path, source: &str, config: &Config) -> Vec<Finding> {
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
            config.detector.entropy_threshold,
            config.detector.min_entropy_len,
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
    entropy_threshold: f64,
    min_entropy_len: usize,
) -> Vec<Finding> {
    let scan = scan_line(line, style, in_block);
    let patterns = known_patterns();
    let mut findings = Vec::new();

    // Apply every named pattern to the full line text.
    for (regex, kind) in &patterns {
        for matched in regex.find_iter(line) {
            let span = (matched.start(), matched.end());
            let literal_span = if range_in_comment(span.0, &scan.comment_ranges) {
                None
            } else {
                full_literal_span(&scan.literals, span)
            };
            findings.push(Finding {
                path: path.to_path_buf(),
                kind: *kind,
                value: matched.as_str().to_string(),
                line_number,
                literal_span,
            });
        }
    }

    // High-entropy fallback: check each quoted literal that wasn't matched above.
    for literal in &scan.literals {
        if range_in_comment(literal.content_span.0, &scan.comment_ranges) {
            continue;
        }
        let content = &line[literal.content_span.0..literal.content_span.1];
        if patterns.iter().any(|(regex, _)| regex.find(content).is_some()) {
            continue;
        }
        if is_high_entropy_token(content, entropy_threshold, min_entropy_len) {
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

/// All known named patterns in priority order.
/// New providers: append here — no other function needs updating.
fn known_patterns() -> Vec<(Regex, SecretKind)> {
    vec![
        (AWS_ACCESS_KEY.clone(),      SecretKind::AwsAccessKey),
        (OPENAI_TOKEN.clone(),        SecretKind::OpenAiToken),
        (JWT_TOKEN.clone(),           SecretKind::JwtToken),
        (GCP_SERVICE_ACCOUNT.clone(), SecretKind::GcpServiceAccount),
        (AZURE_STORAGE.clone(),       SecretKind::AzureStorage),
        (GITHUB_TOKEN.clone(),        SecretKind::GitHubToken),
        (SLACK_TOKEN.clone(),         SecretKind::SlackToken),
        (SLACK_WEBHOOK.clone(),       SecretKind::SlackWebhook),
        (STRIPE_SECRET_KEY.clone(),   SecretKind::StripeSecretKey),
        (GOOGLE_API_KEY.clone(),      SecretKind::GoogleApiKey),
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

fn is_high_entropy_token(value: &str, entropy_threshold: f64, min_entropy_len: usize) -> bool {
    if value.len() < min_entropy_len {
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
    has_upper && has_lower && has_digit && shannon_entropy(value) >= entropy_threshold
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
        assert!(!is_high_entropy_token("aaaaaaaaaaaaaaaaaaaaaaaa", ENTROPY_THRESHOLD, MIN_ENTROPY_LEN));
        assert!(is_high_entropy_token(unique, ENTROPY_THRESHOLD, MIN_ENTROPY_LEN));
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

    // ── Step 2: new pattern tests ────────────────────────────────────────────

    #[test]
    fn detects_github_classic_pat() {
        // ghp_ + exactly 36 alphanumeric characters = 40 chars total
        let token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcd";
        // Trim to exactly 40 chars (ghp_ + 36)
        let token = &token[..40];
        let source = format!("const token = \"{token}\";\n");
        let findings = detect_text(Path::new("config.js"), &source);
        assert!(
            findings.iter().any(|f| f.kind == SecretKind::GitHubToken && f.value == token),
            "should detect GitHub classic PAT"
        );
    }

    #[test]
    fn detects_github_fine_grained_pat() {
        // github_pat_ + exactly 82 chars (alphanumeric+underscore)
        let suffix = "aB3dEf7gHi_".repeat(7) + "aB3dEf7gH"; // 11*7+9 = 86 — trim to 82
        let suffix = &suffix[..82];
        let token = format!("github_pat_{suffix}");
        let source = format!("token = \"{token}\"\n");
        let findings = detect_text(Path::new("secrets.py"), &source);
        assert!(
            findings.iter().any(|f| f.kind == SecretKind::GitHubToken),
            "should detect GitHub fine-grained PAT"
        );
    }

    #[test]
    fn detects_slack_bot_token() {
        // Build at runtime so GitHub push-protection never sees a literal secret.
        // Real Slack tokens have the form: xoxb-{workspace}-{bot}-{secret}
        let token = ["xoxb", "123456789012", "123456789012", "AbCdEfGhIj"].join("-");
        let source = format!("const slackToken = \"{token}\";\n");
        let findings = detect_text(Path::new("app.ts"), &source);
        assert!(
            findings.iter().any(|f| f.kind == SecretKind::SlackToken),
            "should detect Slack bot token"
        );
    }

    #[test]
    fn detects_slack_webhook_url() {
        // Split across a join so the literal URL never appears in source.
        let webhook = [
            "https://hooks.slack.com/services",
            "T00000000",
            "B00000000",
            "XXXXXXXXXXXXXXXXXXXXXXXX",
        ]
        .join("/");
        let source = format!("webhook_url = \"{webhook}\"\n");
        let findings = detect_text(Path::new("config.py"), &source);
        assert!(
            findings.iter().any(|f| f.kind == SecretKind::SlackWebhook && f.value == webhook),
            "should detect Slack webhook URL"
        );
    }

    #[test]
    fn detects_stripe_live_secret_key() {
        // Constructed at runtime — no literal sk_live_ string in source.
        let key = ["sk", "live", "abcdefghijklmnopqrstuvwx"].join("_");
        let source = format!("stripe_key = \"{key}\"\n");
        let findings = detect_text(Path::new("payments.py"), &source);
        assert!(
            findings.iter().any(|f| f.kind == SecretKind::StripeSecretKey && f.value == key),
            "should detect Stripe live secret key"
        );
    }

    #[test]
    fn detects_stripe_restricted_key() {
        // Constructed at runtime — no literal rk_live_ string in source.
        let key = ["rk", "live", "ABCDEFGHIJKLMNOPQRSTUVWXYZ12"].join("_");
        let source = format!("const stripeKey = \"{key}\";\n");
        let findings = detect_text(Path::new("billing.js"), &source);
        assert!(
            findings.iter().any(|f| f.kind == SecretKind::StripeSecretKey && f.value == key),
            "should detect Stripe restricted live key"
        );
    }

    #[test]
    fn detects_google_api_key() {
        // AIza + exactly 35 base64url chars = 39 chars total.
        // Built at runtime to avoid GitHub push-protection flagging the prefix.
        let key = "AIza".to_string() + "SyD-aBcDeFgHiJkLmNoPqRsTuVwXyZ12345";
        assert_eq!(key.len(), 39, "test key must be exactly 39 chars");
        let source = format!("const apiKey = \"{key}\";\n");
        let findings = detect_text(Path::new("maps.js"), &source);
        assert!(
            findings.iter().any(|f| f.kind == SecretKind::GoogleApiKey && f.value == key),
            "should detect Google API key"
        );
    }

    #[test]
    fn does_not_flag_stripe_test_keys() {
        // sk_test_ / rk_test_ must NOT be flagged (only live keys are sensitive).
        // Built at runtime so the literal is never a scannable secret.
        let test_key = ["sk", "test", "abcdefghijklmnopqrstuvwx"].join("_");
        let source = format!("stripe_key = \"{test_key}\"\n");
        let findings = detect_text(Path::new("test_config.py"), &source);
        assert!(
            !findings.iter().any(|f| f.kind == SecretKind::StripeSecretKey),
            "should NOT flag Stripe test keys (sk_test_ / rk_test_)"
        );
    }

    #[test]
    fn all_new_kinds_have_env_base_and_display() {
        let kinds = [
            SecretKind::GitHubToken,
            SecretKind::SlackToken,
            SecretKind::SlackWebhook,
            SecretKind::StripeSecretKey,
            SecretKind::GoogleApiKey,
        ];
        for kind in kinds {
            assert!(!kind.env_base().is_empty(), "{kind} env_base must not be empty");
            assert!(!kind.to_string().is_empty(), "{kind} Display must not be empty");
        }
    }

    #[test]
    fn config_ignores_allowlisted_secret_patterns() {
        let mut config = Config::default();
        config.ignore.patterns.push("AKIAIOSFODNN7EXAMPLE".to_string());

        let temp_dir = std::env::temp_dir().join("secretsentry_cfg_ignore_test");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();
        let file_path = temp_dir.join("sample.py");
        fs::write(&file_path, "aws_key = \"AKIAIOSFODNN7EXAMPLE\"\n").unwrap();

        let findings = detect_with_config(&[file_path], &config).unwrap();
        assert!(findings.is_empty(), "allowlisted secret must be ignored");

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
