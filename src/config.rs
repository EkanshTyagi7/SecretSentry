//! Configuration loader for `.secretsentry.toml`.
//!
//! Provides zero-dependency TOML configuration parsing with support for:
//! - Section headers (`[scan]`, `[detector]`, `[ignore]`, `[remediator]`)
//! - String, integer, float, and boolean values
//! - String arrays (`["item1", "item2"]`)
//! - Comments (`# ...`) and whitespace tolerance

use std::fs;
use std::path::{Path, PathBuf};

pub const CONFIG_FILE_NAME: &str = ".secretsentry.toml";

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub scan: ScanConfig,
    pub detector: DetectorConfig,
    pub ignore: IgnoreConfig,
    pub remediator: RemediatorConfig,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScanConfig {
    pub max_file_bytes: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DetectorConfig {
    pub entropy_threshold: f64,
    pub min_entropy_len: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IgnoreConfig {
    pub files: Vec<String>,
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RemediatorConfig {
    pub create_env_example: bool,
    pub update_gitignore: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            scan: ScanConfig {
                max_file_bytes: 1024 * 1024,
            },
            detector: DetectorConfig {
                entropy_threshold: 4.5,
                min_entropy_len: 20,
            },
            ignore: IgnoreConfig {
                files: Vec::new(),
                patterns: Vec::new(),
            },
            remediator: RemediatorConfig {
                create_env_example: true,
                update_gitignore: true,
            },
        }
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Parse {
        path: PathBuf,
        line: usize,
        message: String,
    },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "reading config {}: {source}", path.display())
            }
            Self::Parse {
                path,
                line,
                message,
            } => {
                write!(f, "{}:{}: parse error: {message}", path.display(), line)
            }
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Look for `.secretsentry.toml` in `root`. If found, parse it; otherwise return `Config::default()`.
    pub fn find_and_load(root: &Path) -> Result<(Self, Option<PathBuf>), ConfigError> {
        let path = root.join(CONFIG_FILE_NAME);
        if path.exists() {
            let config = Self::load_from_file(&path)?;
            Ok((config, Some(path)))
        } else {
            Ok((Self::default(), None))
        }
    }

    /// Load and parse config from an explicit file path.
    pub fn load_from_file(path: &Path) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse_str(&content, path)
    }

    /// Parse configuration from a TOML string.
    pub fn parse_str(content: &str, path: &Path) -> Result<Self, ConfigError> {
        let mut config = Self::default();
        let mut current_section = String::new();

        let mut multi_array_key: Option<String> = None;
        let mut multi_array_values: Vec<String> = Vec::new();
        let mut multi_array_start_line = 0;

        for (idx, raw_line) in content.lines().enumerate() {
            let line_number = idx + 1;
            let stripped = strip_comment(raw_line).trim();

            if let Some(key) = multi_array_key.take() {
                if let Some(end_idx) = stripped.find(']') {
                    let before_bracket = &stripped[..end_idx];
                    let items = parse_comma_separated_strings(before_bracket).map_err(|err| {
                        ConfigError::Parse {
                            path: path.to_path_buf(),
                            line: line_number,
                            message: err,
                        }
                    })?;
                    multi_array_values.extend(items);

                    apply_key_value(
                        &mut config,
                        &current_section,
                        &key,
                        ParsedValue::StringArray(multi_array_values.clone()),
                        path,
                        multi_array_start_line,
                    )?;
                    multi_array_values.clear();
                } else {
                    let items = parse_comma_separated_strings(stripped).map_err(|err| {
                        ConfigError::Parse {
                            path: path.to_path_buf(),
                            line: line_number,
                            message: err,
                        }
                    })?;
                    multi_array_values.extend(items);
                    multi_array_key = Some(key);
                }
                continue;
            }

            if stripped.is_empty() {
                continue;
            }

            if stripped.starts_with('[') && stripped.ends_with(']') {
                let section = stripped[1..stripped.len() - 1].trim().to_ascii_lowercase();
                current_section = section;
                continue;
            }

            if let Some((raw_key, raw_val)) = stripped.split_once('=') {
                let key = raw_key.trim().to_ascii_lowercase();
                let val = raw_val.trim();

                if val.starts_with('[') && !val.ends_with(']') {
                    let after_bracket = &val[1..];
                    let items = parse_comma_separated_strings(after_bracket).map_err(|err| {
                        ConfigError::Parse {
                            path: path.to_path_buf(),
                            line: line_number,
                            message: err,
                        }
                    })?;
                    multi_array_values = items;
                    multi_array_key = Some(key);
                    multi_array_start_line = line_number;
                    continue;
                }

                let parsed_val = parse_value(val).map_err(|err| ConfigError::Parse {
                    path: path.to_path_buf(),
                    line: line_number,
                    message: err,
                })?;

                apply_key_value(
                    &mut config,
                    &current_section,
                    &key,
                    parsed_val,
                    path,
                    line_number,
                )?;
            } else {
                return Err(ConfigError::Parse {
                    path: path.to_path_buf(),
                    line: line_number,
                    message: format!("unexpected line syntax: '{stripped}'"),
                });
            }
        }

        if let Some(key) = multi_array_key {
            return Err(ConfigError::Parse {
                path: path.to_path_buf(),
                line: multi_array_start_line,
                message: format!("unterminated array for key '{key}'"),
            });
        }

        Ok(config)
    }

    /// Check if a relative or absolute file path matches any entry in `ignore.files`.
    pub fn is_file_ignored(&self, path: &Path) -> bool {
        if self.ignore.files.is_empty() {
            return false;
        }
        let normalized = path.to_string_lossy().replace('\\', "/");
        self.ignore.files.iter().any(|pattern| {
            let p = pattern.replace('\\', "/");
            normalized.ends_with(&p)
                || normalized.contains(&p)
                || path.file_name().and_then(|n| n.to_str()) == Some(pattern.as_str())
        })
    }

    /// Check if a secret value matches any entry in `ignore.patterns`.
    pub fn is_secret_ignored(&self, value: &str) -> bool {
        self.ignore.patterns.iter().any(|pattern| pattern == value)
    }
}

#[allow(dead_code)]
enum ParsedValue {
    String(String),
    Bool(bool),
    Int(i64),
    Float(f64),
    StringArray(Vec<String>),
}

fn parse_value(val: &str) -> Result<ParsedValue, String> {
    let val = val.trim();
    if val.eq_ignore_ascii_case("true") {
        return Ok(ParsedValue::Bool(true));
    }
    if val.eq_ignore_ascii_case("false") {
        return Ok(ParsedValue::Bool(false));
    }
    if (val.starts_with('"') && val.ends_with('"') && val.len() >= 2)
        || (val.starts_with('\'') && val.ends_with('\'') && val.len() >= 2)
    {
        return Ok(ParsedValue::String(val[1..val.len() - 1].to_string()));
    }
    if val.starts_with('[') && val.ends_with(']') {
        let inner = &val[1..val.len() - 1];
        let items = parse_comma_separated_strings(inner)?;
        return Ok(ParsedValue::StringArray(items));
    }
    if let Ok(int_val) = val.parse::<i64>() {
        return Ok(ParsedValue::Int(int_val));
    }
    if let Ok(float_val) = val.parse::<f64>() {
        return Ok(ParsedValue::Float(float_val));
    }
    Err(format!("invalid value format: '{val}'"))
}

fn parse_comma_separated_strings(inner: &str) -> Result<Vec<String>, String> {
    let mut items = Vec::new();
    let parts = split_outside_quotes(inner, ',');
    for part in parts {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        if (trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2)
            || (trimmed.starts_with('\'') && trimmed.ends_with('\'') && trimmed.len() >= 2)
        {
            items.push(trimmed[1..trimmed.len() - 1].to_string());
        } else if !trimmed.contains(['"', '\'', '=', '[', ']', '{', '}']) {
            items.push(trimmed.to_string());
        } else {
            return Err(format!("array element must be a string: '{trimmed}'"));
        }
    }
    Ok(items)
}

fn apply_key_value(
    config: &mut Config,
    section: &str,
    key: &str,
    val: ParsedValue,
    path: &Path,
    line: usize,
) -> Result<(), ConfigError> {
    match section {
        "scan" => match key {
            "max_file_bytes" => match val {
                ParsedValue::Int(i) if i >= 0 => config.scan.max_file_bytes = i as u64,
                _ => return Err(expected_err(path, line, "positive integer for max_file_bytes")),
            },
            "entropy_threshold" => match val {
                ParsedValue::Float(f) => config.detector.entropy_threshold = f,
                ParsedValue::Int(i) => config.detector.entropy_threshold = i as f64,
                _ => return Err(expected_err(path, line, "float for entropy_threshold")),
            },
            "files" | "ignored_paths" => match val {
                ParsedValue::StringArray(arr) => config.ignore.files.extend(arr),
                _ => return Err(expected_err(path, line, "string array for ignored paths")),
            },
            _ => {}
        },
        "detector" => match key {
            "entropy_threshold" | "min_entropy" => match val {
                ParsedValue::Float(f) => config.detector.entropy_threshold = f,
                ParsedValue::Int(i) => config.detector.entropy_threshold = i as f64,
                _ => return Err(expected_err(path, line, "float for entropy_threshold")),
            },
            "min_entropy_len" => match val {
                ParsedValue::Int(i) if i >= 0 => config.detector.min_entropy_len = i as usize,
                _ => return Err(expected_err(path, line, "positive integer for min_entropy_len")),
            },
            _ => {}
        },
        "ignore" => match key {
            "files" | "ignored_paths" => match val {
                ParsedValue::StringArray(arr) => config.ignore.files.extend(arr),
                _ => return Err(expected_err(path, line, "string array for ignored files")),
            },
            "patterns" | "secrets" => match val {
                ParsedValue::StringArray(arr) => config.ignore.patterns.extend(arr),
                _ => return Err(expected_err(path, line, "string array for ignored patterns")),
            },
            _ => {}
        },
        "remediator" => match key {
            "create_env_example" | "env_example" => match val {
                ParsedValue::Bool(b) => config.remediator.create_env_example = b,
                _ => return Err(expected_err(path, line, "boolean for create_env_example")),
            },
            "update_gitignore" | "gitignore" => match val {
                ParsedValue::Bool(b) => config.remediator.update_gitignore = b,
                _ => return Err(expected_err(path, line, "boolean for update_gitignore")),
            },
            _ => {}
        },
        _ => {}
    }
    Ok(())
}

fn expected_err(path: &Path, line: usize, expected: &str) -> ConfigError {
    ConfigError::Parse {
        path: path.to_path_buf(),
        line,
        message: format!("expected {expected}"),
    }
}

fn strip_comment(line: &str) -> &str {
    let mut in_quote = None;
    for (i, c) in line.char_indices() {
        if let Some(q) = in_quote {
            if c == q {
                in_quote = None;
            }
        } else if c == '"' || c == '\'' {
            in_quote = Some(c);
        } else if c == '#' {
            return &line[..i];
        }
    }
    line
}

fn split_outside_quotes(s: &str, delimiter: char) -> Vec<&str> {
    let mut result = Vec::new();
    let mut in_quote = None;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        if let Some(q) = in_quote {
            if c == q {
                in_quote = None;
            }
        } else if c == '"' || c == '\'' {
            in_quote = Some(c);
        } else if c == delimiter {
            result.push(&s[start..i]);
            start = i + c.len_utf8();
        }
    }
    result.push(&s[start..]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_toml_config() {
        let toml = r#"
# SecretSentry project configuration
[scan]
max_file_bytes = 2097152

[detector]
entropy_threshold = 4.8
min_entropy_len = 24

[ignore]
files = [
    "legacy_config.py",
    "tests/fixtures"
]
patterns = ["DUMMY_KEY_1234567890", "TEST_SECRET_ABC"]

[remediator]
create_env_example = false
update_gitignore = true
"#;
        let config = Config::parse_str(toml, Path::new(".secretsentry.toml")).unwrap();
        assert_eq!(config.scan.max_file_bytes, 2097152);
        assert_eq!(config.detector.entropy_threshold, 4.8);
        assert_eq!(config.detector.min_entropy_len, 24);
        assert_eq!(config.ignore.files, vec!["legacy_config.py", "tests/fixtures"]);
        assert_eq!(
            config.ignore.patterns,
            vec!["DUMMY_KEY_1234567890", "TEST_SECRET_ABC"]
        );
        assert!(!config.remediator.create_env_example);
        assert!(config.remediator.update_gitignore);

        assert!(config.is_file_ignored(Path::new("src/legacy_config.py")));
        assert!(config.is_file_ignored(Path::new("tests/fixtures/sample.json")));
        assert!(!config.is_file_ignored(Path::new("src/main.rs")));

        assert!(config.is_secret_ignored("DUMMY_KEY_1234567890"));
        assert!(!config.is_secret_ignored("AKIAREALKEY12345678"));
    }

    #[test]
    fn default_config_when_file_missing() {
        let temp_dir = std::env::temp_dir().join("secretsentry_empty_cfg_test");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let (config, loaded_path) = Config::find_and_load(&temp_dir).unwrap();
        assert_eq!(config, Config::default());
        assert!(loaded_path.is_none());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn parses_unquoted_array_elements_and_tolerates_loose_syntax() {
        let toml = r#"
[ignore]
files = [legacy.py, vendor/bundle]
patterns = ["SECRET_1", SECRET_2]
"#;
        let config = Config::parse_str(toml, Path::new("test.toml")).unwrap();
        assert_eq!(config.ignore.files, vec!["legacy.py", "vendor/bundle"]);
        assert_eq!(config.ignore.patterns, vec!["SECRET_1", "SECRET_2"]);
    }
}
