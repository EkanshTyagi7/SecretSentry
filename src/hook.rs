//! Git pre-commit hook generator and installer.
//!
//! Installs a hook in `.git/hooks/pre-commit` to prevent committing hardcoded secrets.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::color::Colors;

pub const HOOK_MARKER: &str = "# --- SecretSentry Pre-commit Hook ---";
pub const HOOK_END_MARKER: &str = "# --- End SecretSentry Pre-commit Hook ---";

#[derive(Debug)]
pub enum HookError {
    NotGitRepo { path: PathBuf },
    Io { path: PathBuf, source: std::io::Error },
}

impl std::fmt::Display for HookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotGitRepo { path } => {
                write!(
                    f,
                    "'{}' is not a git repository (missing .git directory)",
                    path.display()
                )
            }
            Self::Io { path, source } => write!(f, "accessing {}: {source}", path.display()),
        }
    }
}

impl std::error::Error for HookError {}

#[derive(Debug, PartialEq, Eq)]
pub enum InstallStatus {
    Created,
    Updated,
    AlreadyPresent,
}

/// Find the `.git` directory for a repository root, resolving git worktrees/submodules if necessary.
pub fn find_git_dir(root: &Path) -> Result<PathBuf, HookError> {
    let dot_git = root.join(".git");
    if dot_git.is_dir() {
        return Ok(dot_git);
    }
    if dot_git.is_file() {
        let content = fs::read_to_string(&dot_git).map_err(|source| HookError::Io {
            path: dot_git.clone(),
            source,
        })?;
        if let Some(rest) = content.trim().strip_prefix("gitdir:") {
            let target = root.join(rest.trim());
            if target.exists() {
                return Ok(target);
            }
        }
    }
    Err(HookError::NotGitRepo {
        path: root.to_path_buf(),
    })
}

/// Generate the hook script snippet.
pub fn hook_script_content() -> String {
    format!(
        "\
{HOOK_MARKER}
# Prevents accidental commits containing hardcoded secrets.

echo \"🛡️  Running SecretSentry pre-commit check...\"

if command -v secretsentry >/dev/null 2>&1; then
    SS_CMD=\"secretsentry . --dry-run --no-color\"
elif cargo --version >/dev/null 2>&1; then
    SS_CMD=\"cargo run --quiet -- . --dry-run --no-color\"
else
    echo \"⚠️  SecretSentry binary not found on PATH and cargo not available; skipping secret scan.\"
    exit 0
fi

SS_OUTPUT=$($SS_CMD 2>&1)

if echo \"$SS_OUTPUT\" | grep -qE \"detected [1-9][0-9]* secrets\"; then
    echo \"❌ SecretSentry: Commit blocked! Hardcoded secrets detected:\"
    echo \"$SS_OUTPUT\"
    echo \"\"
    echo \"💡 Run 'secretsentry .' to remediate or update .secretsentry.toml to ignore false positives.\"
    exit 1
fi

echo \"✅ SecretSentry: No secrets detected.\"
{HOOK_END_MARKER}
"
    )
}

/// Install or update the `.git/hooks/pre-commit` hook in `root`.
pub fn install_hook(root: &Path) -> Result<InstallStatus, HookError> {
    let git_dir = find_git_dir(root)?;
    let hooks_dir = git_dir.join("hooks");
    if !hooks_dir.exists() {
        fs::create_dir_all(&hooks_dir).map_err(|source| HookError::Io {
            path: hooks_dir.clone(),
            source,
        })?;
    }

    let hook_path = hooks_dir.join("pre-commit");
    let script = hook_script_content();

    let status = if hook_path.exists() {
        let existing = fs::read_to_string(&hook_path).map_err(|source| HookError::Io {
            path: hook_path.clone(),
            source,
        })?;

        if existing.contains(HOOK_MARKER) {
            // Replace existing SecretSentry section cleanly
            if let (Some(start_idx), Some(end_idx)) =
                (existing.find(HOOK_MARKER), existing.find(HOOK_END_MARKER))
            {
                let before = &existing[..start_idx];
                let after = &existing[end_idx + HOOK_END_MARKER.len()..];
                let mut updated = String::with_capacity(existing.len() + script.len());
                updated.push_str(before);
                updated.push_str(&script);
                if after.starts_with('\n') {
                    updated.push_str(&after[1..]);
                } else {
                    updated.push_str(after);
                }

                if updated == existing {
                    return Ok(InstallStatus::AlreadyPresent);
                }

                fs::write(&hook_path, updated).map_err(|source| HookError::Io {
                    path: hook_path.clone(),
                    source,
                })?;
                InstallStatus::Updated
            } else {
                return Ok(InstallStatus::AlreadyPresent);
            }
        } else {
            // Append to existing pre-commit hook
            let mut file = OpenOptions::new()
                .append(true)
                .open(&hook_path)
                .map_err(|source| HookError::Io {
                    path: hook_path.clone(),
                    source,
                })?;

            let prefix = if existing.ends_with('\n') { "\n" } else { "\n\n" };
            file.write_all(format!("{prefix}{script}").as_bytes())
                .map_err(|source| HookError::Io {
                    path: hook_path.clone(),
                    source,
                })?;
            InstallStatus::Updated
        }
    } else {
        // Create new hook script
        let content = format!("#!/bin/sh\n\n{script}");
        fs::write(&hook_path, content).map_err(|source| HookError::Io {
            path: hook_path.clone(),
            source,
        })?;
        InstallStatus::Created
    };

    // On Unix platforms, make sure executable permissions (0o755) are set
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(&hook_path) {
            let mut perms = metadata.permissions();
            perms.set_mode(0o755);
            let _ = fs::set_permissions(&hook_path, perms);
        }
    }

    Ok(status)
}

/// Print hook installation result to console with colors.
pub fn print_install_result(root: &Path, status: InstallStatus, colors: &Colors) {
    let hook_rel = root.join(".git").join("hooks").join("pre-commit");
    match status {
        InstallStatus::Created => {
            println!(
                "{} pre-commit hook at {}",
                colors.bold_green("installed"),
                colors.cyan(&hook_rel.display().to_string())
            );
            println!(
                "{}",
                colors.dim("Git will now run SecretSentry before every commit and block secret leaks.")
            );
        }
        InstallStatus::Updated => {
            println!(
                "{} pre-commit hook at {}",
                colors.bold_green("updated"),
                colors.cyan(&hook_rel.display().to_string())
            );
            println!(
                "{}",
                colors.dim("Existing pre-commit hook preserved; SecretSentry check updated.")
            );
        }
        InstallStatus::AlreadyPresent => {
            println!(
                "{} pre-commit hook at {} is already up to date",
                colors.bold_yellow("info:"),
                colors.cyan(&hook_rel.display().to_string())
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fails_on_non_git_directory() {
        let temp_dir = std::env::temp_dir().join("secretsentry_not_git_test");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let result = install_hook(&temp_dir);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), HookError::NotGitRepo { .. }));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn installs_new_hook_in_git_repo() {
        let temp_dir = std::env::temp_dir().join("secretsentry_hook_install_test");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(temp_dir.join(".git")).unwrap();

        let status = install_hook(&temp_dir).unwrap();
        assert_eq!(status, InstallStatus::Created);

        let hook_file = temp_dir.join(".git").join("hooks").join("pre-commit");
        assert!(hook_file.exists());
        let content = fs::read_to_string(&hook_file).unwrap();
        assert!(content.starts_with("#!/bin/sh"));
        assert!(content.contains(HOOK_MARKER));
        assert!(content.contains(HOOK_END_MARKER));

        // Reinstalling should report AlreadyPresent
        let second_status = install_hook(&temp_dir).unwrap();
        assert_eq!(second_status, InstallStatus::AlreadyPresent);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn appends_to_existing_hook_preserving_other_commands() {
        let temp_dir = std::env::temp_dir().join("secretsentry_hook_append_test");
        let _ = fs::remove_dir_all(&temp_dir);
        let hooks_dir = temp_dir.join(".git").join("hooks");
        fs::create_dir_all(&hooks_dir).unwrap();

        let existing_hook = "#!/bin/sh\necho 'running linter'\nnpm test\n";
        fs::write(hooks_dir.join("pre-commit"), existing_hook).unwrap();

        let status = install_hook(&temp_dir).unwrap();
        assert_eq!(status, InstallStatus::Updated);

        let content = fs::read_to_string(hooks_dir.join("pre-commit")).unwrap();
        assert!(content.contains("echo 'running linter'"));
        assert!(content.contains("npm test"));
        assert!(content.contains(HOOK_MARKER));

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
