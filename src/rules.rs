//! YARA rule synchronisation — YARA Forge and Elastic.
//!
//! ## YARA Forge
//! Three tiers, each published as a ZIP containing a single consolidated `.yar`:
//!
//! | Tier     | Rules | Use case                                    |
//! |----------|-------|---------------------------------------------|
//! | core     | ~5k   | High accuracy, low FP, best performance     |
//! | extended | ~10k  | Broader coverage, slight FP/perf increase   |
//! | full     | ~11k  | All operational rules, highest coverage     |
//!
//! ## Elastic
//! ~1,000+ individual `.yar` files from the Elastic Security protections
//! repository, licensed under the Elastic License 2.0.  Requires explicit
//! license acceptance via `--accept-elastic-license` at the command line.

use anyhow::{anyhow, Context, Result};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::fs;
use std::io::Cursor;
use std::path::Path;
use std::time::Duration;

// ─────────────────────────────────────────────────────────────────────────────
// YARA Forge rule set
// ─────────────────────────────────────────────────────────────────────────────

/// The three YARA Forge rule tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSet {
    Core,
    Extended,
    Full,
}

impl RuleSet {
    /// Parse from the string the user typed.
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "core"     => Ok(Self::Core),
            "extended" => Ok(Self::Extended),
            "full"     => Ok(Self::Full),
            other => Err(anyhow!(
                "unknown rule set '{}'. Valid options: core, extended, full",
                other
            )),
        }
    }

    /// Human-readable name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Core     => "core",
            Self::Extended => "extended",
            Self::Full     => "full",
        }
    }

    /// Download URL for the ZIP archive.
    pub fn url(self) -> &'static str {
        match self {
            Self::Core =>
                "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip",
            Self::Extended =>
                "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-extended.zip",
            Self::Full =>
                "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip",
        }
    }

    /// Approximate rule count shown in the progress message.
    pub fn approx_rules(self) -> &'static str {
        match self {
            Self::Core     => "~5k",
            Self::Extended => "~10k",
            Self::Full     => "~11k",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP client helper
// ─────────────────────────────────────────────────────────────────────────────

fn build_client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .user_agent(concat!("yscanfs/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(300))
        .build()
        .context("failed to build HTTP client")
}

fn spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("  {spinner:.cyan} {msg}")
            .unwrap()
            .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ "),
    );
    pb.enable_steady_tick(Duration::from_millis(80));
    pb.set_message(msg.to_string());
    pb
}

// ─────────────────────────────────────────────────────────────────────────────
// YARA Forge sync
// ─────────────────────────────────────────────────────────────────────────────

/// Download the YARA Forge rule set and write it into `rules_dir`.
///
/// YARA Forge packages each tier as a ZIP containing a single consolidated
/// `.yar` file.  This function extracts that file into `rules_dir`, replacing
/// any previously downloaded YARA Forge rule file.
pub fn sync_rules(rules_dir: &Path, ruleset: RuleSet) -> Result<()> {
    fs::create_dir_all(rules_dir)
        .with_context(|| format!("cannot create rules directory '{}'", rules_dir.display()))?;

    let pb = spinner(&format!(
        "Connecting to YARA Forge ({} set, {} rules)…",
        ruleset.name(),
        ruleset.approx_rules(),
    ));

    let client = build_client()?;

    let resp = client
        .get(ruleset.url())
        .send()
        .context("GET request to YARA Forge failed")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "YARA Forge returned HTTP {}: {}",
            resp.status().as_u16(),
            resp.status().canonical_reason().unwrap_or("unknown")
        ));
    }

    pb.set_message("Downloading archive…");
    let bytes = resp.bytes().context("failed to read response body")?;

    pb.set_message("Extracting rules…");

    // YARA Forge ZIPs contain a single consolidated `.yar` file.
    let cursor = Cursor::new(bytes);
    let mut archive =
        zip::ZipArchive::new(cursor).context("failed to parse ZIP archive")?;

    let mut extracted = false;

    for i in 0..archive.len() {
        let mut zf = archive
            .by_index(i)
            .with_context(|| format!("failed to read ZIP entry {}", i))?;

        let name = zf.name().to_owned();
        if !name.ends_with(".yar") {
            continue;
        }

        let filename = std::path::Path::new(&name)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();

        if filename.is_empty() {
            continue;
        }

        let dest = rules_dir.join(filename);
        let mut out = fs::File::create(&dest)
            .with_context(|| format!("cannot create '{}'", dest.display()))?;

        std::io::copy(&mut zf, &mut out)
            .with_context(|| format!("cannot write '{}'", dest.display()))?;

        pb.finish_and_clear();

        // Count rules in the extracted file for the confirmation message.
        let rule_count = fs::read_to_string(&dest)
            .map(|s| s.lines().filter(|l| {
                let t = l.trim_start();
                t.starts_with("rule ")
                    || t.starts_with("private rule ")
                    || t.starts_with("global rule ")
                    || t.starts_with("private global rule ")
                    || t.starts_with("global private rule ")
            }).count())
            .unwrap_or(0);

        println!(
            "  {} YARA Forge {} rules ({} rules) → {}",
            "✓".green().bold(),
            ruleset.name(),
            rule_count,
            dest.display(),
        );

        extracted = true;
        break;
    }

    if !extracted {
        pb.finish_and_clear();
        return Err(anyhow!(
            "no .yar file found inside the YARA Forge {} archive",
            ruleset.name()
        ));
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Elastic sync
// ─────────────────────────────────────────────────────────────────────────────

/// Elastic protections-artifacts repository ZIP archive (main branch).
///
/// Downloading the full repo ZIP is far more efficient than making one HTTP
/// request per rule file (~1,000+ files).  We extract only the
/// `yara/rules/*.yar` entries into `rules_dir`.
const ELASTIC_REPO_ZIP: &str =
    "https://github.com/elastic/protections-artifacts/archive/refs/heads/main.zip";

/// The path prefix inside the ZIP where Elastic YARA rules live.
const ELASTIC_RULES_PREFIX: &str = "protections-artifacts-main/yara/rules/";

/// Download Elastic Security YARA rules into `rules_dir`.
///
/// These rules are licensed under the **Elastic License 2.0** which restricts
/// use in competing products.  The caller is responsible for ensuring the user
/// has explicitly accepted the license via the `--accept-elastic-license` flag
/// before calling this function.
///
/// Rule files are written to a subdirectory `elastic/` inside `rules_dir` to
/// keep them clearly separated from YARA Forge rules.
pub fn sync_elastic_rules(rules_dir: &Path) -> Result<()> {
    let elastic_dir = rules_dir.join("elastic");
    fs::create_dir_all(&elastic_dir)
        .with_context(|| format!("cannot create '{}'", elastic_dir.display()))?;

    let pb = spinner("Connecting to Elastic protections-artifacts…");

    let client = build_client()?;

    let resp = client
        .get(ELASTIC_REPO_ZIP)
        .send()
        .context("GET request to Elastic repository failed")?;

    if !resp.status().is_success() {
        pb.finish_and_clear();
        return Err(anyhow!(
            "Elastic repository returned HTTP {}: {}",
            resp.status().as_u16(),
            resp.status().canonical_reason().unwrap_or("unknown")
        ));
    }

    pb.set_message("Downloading Elastic rules archive…");
    let bytes = resp.bytes().context("failed to read response body")?;

    pb.set_message("Extracting Elastic rules…");

    let cursor = Cursor::new(bytes);
    let mut archive =
        zip::ZipArchive::new(cursor).context("failed to parse ZIP archive")?;

    let mut extracted = 0usize;

    for i in 0..archive.len() {
        let mut zf = archive
            .by_index(i)
            .with_context(|| format!("failed to read ZIP entry {}", i))?;

        let name = zf.name().to_owned();

        // Only extract files under the yara/rules/ directory.
        if !name.starts_with(ELASTIC_RULES_PREFIX) || !name.ends_with(".yar") {
            continue;
        }

        let filename = std::path::Path::new(&name)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();

        if filename.is_empty() {
            continue;
        }

        let dest = elastic_dir.join(filename);
        let mut out = fs::File::create(&dest)
            .with_context(|| format!("cannot create '{}'", dest.display()))?;

        std::io::copy(&mut zf, &mut out)
            .with_context(|| format!("cannot write '{}'", dest.display()))?;

        extracted += 1;
        pb.set_message(format!("Extracting Elastic rules… {} files", extracted));
    }

    pb.finish_and_clear();

    if extracted == 0 {
        return Err(anyhow!(
            "no .yar files found in the Elastic repository archive — \
             the repository structure may have changed"
        ));
    }

    // Count total rules across all extracted files.
    let rule_count: usize = std::fs::read_dir(&elastic_dir)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path().extension()
                .and_then(|x| x.to_str())
                .map(|x| x == "yar")
                .unwrap_or(false)
        })
        .filter_map(|e| fs::read_to_string(e.path()).ok())
        .map(|src| {
            src.lines().filter(|l| {
                let t = l.trim_start();
                t.starts_with("rule ")
                    || t.starts_with("private rule ")
                    || t.starts_with("global rule ")
                    || t.starts_with("private global rule ")
                    || t.starts_with("global private rule ")
            }).count()
        })
        .sum();

    println!(
        "  {} Elastic Security rules ({} rules) → {}",
        "✓".green().bold(),
        rule_count,
        elastic_dir.display(),
    );

    Ok(())
}
