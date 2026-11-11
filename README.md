# 🛡️ SecretSentry

[![Rust](https://img.shields.io/badge/rust-2024%20edition-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
[![Tests](https://img.shields.io/badge/self--test-53%20checks%20passed-brightgreen.svg)](#built-in-self-test)
[![Status](https://img.shields.io/badge/status-active-success.svg)](#)

**SecretSentry** is a fast, concurrent CLI security tool written in Rust. It scans codebases for hardcoded credentials, extracts them into `.env`, auto-generates sanitized `.env.example` templates, secures `.gitignore`, and automatically rewrites source code literals into environment variable lookups.

---

## 🌟 Key Features

- 🔍 **Multi-Provider Secret Detection**: Identifies cloud API keys, OAuth tokens, webhooks, JWTs, and high-entropy strings across 10 pattern providers.
- ⚡ **High-Performance Parallelism**: Concurrent file traversal (`ignore` / `.gitignore` compliant) and multi-threaded file rewriting powered by `rayon`.
- 🔄 **Automatic Source Code Rewriting**: Replaces raw secret literals with language-specific environment variable lookups:
  - **Python**: `os.getenv("KEY")`
  - **JavaScript / TypeScript**: `process.env.KEY`
  - **Rust**: `std::env::var("KEY").unwrap()`
- 📋 **`.env.example` Generation**: Automatically writes or merges placeholder values (e.g., `AWS_ACCESS_KEY_ID=your_aws_access_key_id_here`) for team onboarding.
- 🔒 **`.gitignore` Protection**: Verifies whether `.env` is covered in `.gitignore` and appends it if missing to prevent secret leaks to version control.
- 🧪 **Safe `--dry-run` Mode**: Previews all detected secrets, proposed code replacements, and file actions without altering files on disk.
- ⚙️ **Project Configuration (`.secretsentry.toml`)**: Tune entropy thresholds, allowlist known test dummy secrets, ignore specific directories or files, and configure `.env` generation.
- 🎨 **ANSI Terminal Formatting**: Clean, colorized findings and banners with automatic Windows VT100 support and `--no-color` / `NO_COLOR` compliance.
- 🛠️ **Integrated Self-Test**: 53-assertion end-to-end sandbox test suite verifiable directly from the CLI via `--self-test`.

---

## 🔎 Supported Secret Detectors

| Provider / Secret Type | Pattern Description | Generated `.env` Key Base |
|---|---|---|
| **AWS Access Key ID** | `AKIA[0-9A-Z]{16}` | `AWS_ACCESS_KEY_ID` |
| **OpenAI API Key** | `sk-[A-Za-z0-9]{32,}` | `OPENAI_API_KEY` |
| **GitHub Token (Classic & Fine-grained)** | `ghp_[0-9A-Za-z]{36}`, `github_pat_[0-9A-Za-z_]{82}` | `GITHUB_TOKEN` |
| **Slack Bot / App Token** | `xox[baprs]-[0-9A-Za-z-]{10,100}` | `SLACK_TOKEN` |
| **Slack Incoming Webhook** | `https://hooks.slack.com/services/...` | `SLACK_WEBHOOK_URL` |
| **Stripe Secret / Restricted Key** | `sk_live_[0-9A-Za-z]{24,}`, `rk_live_[0-9A-Za-z]{24,}` | `STRIPE_SECRET_KEY` |
| **Google Cloud API Key** | `AIza[0-9A-Za-z\\-_]{35}` | `GOOGLE_API_KEY` |
| **Google Cloud Service Account** | `"private_key_id": "[0-9a-f]{40}"` | `GCP_PRIVATE_KEY_ID` |
| **Azure Storage Connection String** | `DefaultEndpointsProtocol=https;AccountName=...` | `AZURE_STORAGE_CONNECTION_STRING` |
| **JSON Web Token (JWT)** | `eyJ...` (base64 header + payload + signature) | `JWT_TOKEN` |
| **High-Entropy Secrets** | Shannon entropy calculation (H ≥ 4.5, len ≥ 20) | `HIGH_ENTROPY_SECRET` |

---

## 🚀 Installation & Setup

### Prerequisites
- [Rust](https://www.rust-lang.org/tools/install) (1.80+ / 2024 edition)
- Cargo package manager

### Build from Source
```bash
# Clone the repository
git clone https://github.com/EkanshTyagi7/SecretSentry.git
cd SecretSentry

# Build optimized release binary
cargo build --release

# The binary will be available at target/release/secretsentry
```

### Install Globally
```bash
cargo install --path .
```

---

## 💻 CLI Usage

```text
SecretSentry

Usage:
  secretsentry <directory> [--dry-run] [--no-color] [--config <path>]
  secretsentry --self-test [--no-color]
  secretsentry --help

Options:
  --dry-run        Preview secrets and planned code changes without modifying files or writing .env
  --no-color       Disable ANSI colored terminal output
  --config <path>  Path to configuration file (default: <directory>/.secretsentry.toml)
  --self-test      Run the integrated self-test suite and validation checks
  -h, --help       Print this help message
```

### Examples

#### 1. Preview changes safely with `--dry-run`
Inspect what secrets are found and what code edits would occur without touching any files:
```bash
secretsentry ./my-project --dry-run
```

#### 2. Scan and remediate a codebase
Extracts secrets to `.env`, creates `.env.example`, updates `.gitignore`, and rewrites source files:
```bash
secretsentry ./my-project
```

#### 3. Use a custom configuration file
```bash
secretsentry ./my-project --config path/to/.secretsentry.toml
```

#### 4. Disable colors (e.g. for CI/CD logging)
```bash
secretsentry ./my-project --no-color
# Or set the environment variable:
NO_COLOR=1 secretsentry ./my-project
```

#### 5. Run the full self-test verification
Runs an isolated sandbox test covering detection, rewriting, `.env` isolation, `.env.example`, and `.gitignore`:
```bash
secretsentry --self-test
```

---

## ⚙️ Configuration File (`.secretsentry.toml`)

Create a `.secretsentry.toml` file in the root of your project to customize scanning and remediation behavior:

```toml
[scan]
# Maximum file size to scan in bytes (default: 1048576 = 1MB)
max_file_bytes = 1048576

[detector]
# Minimum Shannon entropy for unlisted high-entropy tokens (default: 4.5)
entropy_threshold = 4.5
# Minimum token length to evaluate for entropy (default: 20)
min_entropy_len = 20

[ignore]
# Files or directory paths to skip during scanning
files = [
    "tests/fixtures",
    "legacy_config.py"
]
# Allowlisted dummy or mock secrets to suppress false positives
patterns = [
    "AKIAIOSFODNN7EXAMPLE",
    "DUMMY_SECRET_KEY_FOR_TESTS"
]

[remediator]
# Automatically generate or merge .env.example with placeholder keys
create_env_example = true
# Ensure .env is added to .gitignore
update_gitignore = true
```

---

## 🏗️ Architecture

```mermaid
flowchart TD
    A["Target Directory"] --> B["Scanner (ignore / gitignore compliant)"]
    B --> C["Detector (Regex + Shannon Entropy)"]
    C --> D{"Mode?"}
    D -- "--dry-run" --> E["Dry Run Preview (Replacements & Stats)"]
    D -- "Live" --> F["Remediator (Rayon Parallelism)"]
    F --> G["Append to .env (Mutex Protected)"]
    F --> H["Generate / Update .env.example"]
    F --> I["Ensure .env in .gitignore"]
    F --> J["Atomic Rewrite Source Code (Rust, Python, JS/TS)"]
```

---

## 🧪 Testing

Run unit tests:
```bash
cargo test
```

Run the integrated sandbox test:
```bash
cargo run -- --self-test
```

---

## 📄 License

Dual-licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
