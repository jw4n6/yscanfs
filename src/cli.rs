//! Command-line interface definitions via clap derive macros.

use clap::Parser;
use colored::Colorize;
use std::path::PathBuf;

fn banner() -> String {
    format!(
        "{}",
        "\
__   __ ____    ____     _     _   _  _____  ____
\\ \\ / // ___|  / ___|   / \\   | \\ | ||  ___|/ ___|
 \\ V / \\___ \\ | |      / _ \\  |  \\| || |_   \\___ \\
  | |   ___) || |___  / ___ \\ | |\\  ||  _|   ___) |
  |_|  |____/  \\____|/_/   \\_\\|_| \\_||_|    |____/"
        .bright_green()
        .bold()
    )
}

/// YARA scanner for forensic disk images.
#[derive(Parser, Debug)]
#[command(
    name = "yscanfs",
    about = "YARA scanner for forensic disk images | https://github.com/jw4n6/yscanfs",
    before_help = banner(),
    long_about = None,
    version,
    arg_required_else_help = true,
)]
pub struct Args {
    // ── Input ──────────────────────────────────────────────────────────────
    /// Path to a disk image file (.E01, .raw, .dd, .img, .bin, .001)
    #[arg(short = 'f', long = "file", value_name = "FILE", conflicts_with = "dir")]
    pub file: Option<PathBuf>,

    /// Directory containing disk images to scan (all supported formats)
    #[arg(short = 'd', long = "dir", value_name = "DIR", conflicts_with = "file")]
    pub dir: Option<PathBuf>,

    // ── General Options ────────────────────────────────────────────────────
    /// Custom YARA rules directory (default: ./rules/)
    #[arg(
        short = 'r',
        long = "rules",
        value_name = "DIR",
        default_value = "./rules/",
        hide_default_value = true,
    )]
    pub rules: PathBuf,

    /// Maximum file size to scan in MB (default: 50 MB)
    #[arg(
        short = 'm',
        long = "max-size",
        value_name = "MB",
        default_value = "50",
        hide_default_value = true,
    )]
    pub max_size: u64,

    /// Hash allowlist — skip files whose SHA-256 is in this file (one hash per line).
    ///
    /// Useful for filtering known-good system files (e.g. from the NSRL hash set).
    /// Lines beginning with '#' are treated as comments.
    #[arg(long = "allowlist", value_name = "FILE")]
    pub allowlist: Option<PathBuf>,

    // ── Output ─────────────────────────────────────────────────────────────
    /// Output file path. Defaults to yscanfs_<timestamp>.csv (or .json)
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Output format: csv (default) or json
    #[arg(
        short = 'F',
        long = "output-format",
        value_name = "FORMAT",
        default_value = "csv",
        hide_default_value = true,
    )]
    pub output_format: String,

    /// Only run rules whose name matches this glob pattern (can repeat).
    ///
    /// Example: --include-rule "Windows_Trojan_*" --include-rule "MAL_*"
    #[arg(long = "include-rule", value_name = "PATTERN")]
    pub include_rule: Vec<String>,

    /// Skip rules whose name matches this glob pattern (can repeat).
    ///
    /// Example: --exclude-rule "PUP_*" --exclude-rule "*_Adware_*"
    #[arg(long = "exclude-rule", value_name = "PATTERN")]
    pub exclude_rule: Vec<String>,

    /// Enable Volume Shadow Copy (VSS) scanning.
    ///
    /// Enumerates all VSS snapshots on NTFS partitions and scans each one.
    /// Snapshot files are labelled in the CSV/JSON output with the path
    /// prefixed by `[VSS#N YYYY-MM-DD]` so hits are clearly attributed
    /// to the specific snapshot they came from.
    /// Useful for detecting malware that was present at a previous point in
    /// time but has since been deleted.
    #[arg(long = "vss")]
    pub vss: bool,

    /// List VSS snapshots found in the image and exit (no scan performed).
    #[arg(long = "list-vss")]
    pub list_vss: bool,

    /// Deduplicate results by (rule, SHA-256).
    ///
    /// When the same file appears in multiple locations and is matched by the
    /// same rule, consolidate into a single row with all paths joined by "; ".
    /// Each unique rule that matches a file still produces its own row —
    /// multiple rules matching the same binary are preserved.
    ///
    /// Example: MAL_Mirai matching the same binary in 4 locations produces
    /// 1 row instead of 4, with the Paths column listing all 4 locations.
    #[arg(long = "unique-files")]
    pub unique_files: bool,

    /// Suppress all output except errors and the final output file path.
    /// Intended for scripting and automation pipelines.
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,

    // ── Rules sync ─────────────────────────────────────────────────────────
    /// Sync YARA rules: core, extended, full (default), or elastic
    #[arg(
        short = 's',
        long = "sync",
        value_name = "RULESET",
        num_args = 0..=1,
        default_missing_value = "full",
        require_equals = false,
        hide_possible_values = true,
        long_help = "Sync YARA rules: core, extended, full (default), or elastic\n\nRule sets:\n  core     — YARA Forge: high accuracy, low FPs (~5k rules)\n  extended — YARA Forge: broader coverage (~10k rules)\n  full     — YARA Forge: all operational rules (~11k rules, default)\n  elastic  — Elastic Security (~1k rules, requires --accept-elastic-license)\n\nExamples:\n  yscanfs --sync\n  yscanfs -s core\n  yscanfs -s elastic --accept-elastic-license"
    )]
    pub sync: Option<String>,

    /// Accept Elastic License 2.0 and download Elastic Security YARA rules
    #[arg(long = "accept-elastic-license")]
    pub accept_elastic_license: bool,

    // ── Diagnostics ────────────────────────────────────────────────────────
    /// Enable debug logging to logs/yscanfs_<timestamp>_debug.log
    #[arg(short = 'D', long = "debug")]
    pub debug: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Output format
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputFormat {
    Csv,
    Json,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> anyhow::Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "csv"  => Ok(Self::Csv),
            "json" => Ok(Self::Json),
            other  => Err(anyhow::anyhow!(
                "unknown output format '{}'. Valid options: csv, json", other
            )),
        }
    }

    pub fn extension(&self) -> &'static str {
        match self { Self::Csv => "csv", Self::Json => "json" }
    }
}
