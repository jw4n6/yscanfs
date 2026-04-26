//! YARA rule loading and file-content scanning.

use anyhow::{anyhow, Result};
use log::warn;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;
use yara_x::{Compiler, Rules};

// ─────────────────────────────────────────────────────────────────────────────
// Rule loading
// ─────────────────────────────────────────────────────────────────────────────

/// Load and compile every `*.yar` and `*.yara` file found (recursively) in `rules_dir`.
///
/// Returns the compiled [`Rules`], the count of successfully loaded rules,
/// and a `HashMap<rule_identifier, source_label>` mapping each rule to its
/// origin (`YARA Forge`, `Elastic Security`, or `Custom`).
pub(crate) fn load_rules(rules_dir: &Path) -> Result<(Rules, usize, HashMap<String, String>)> {
    if !rules_dir.exists() {
        return Err(anyhow!(
            "rules directory '{}' does not exist. Run with --sync to download rules.",
            rules_dir.display()
        ));
    }

    // Each entry is (source_text, source_label) so we can build the
    // rule_name → source_label map after final compilation.
    let mut clean: Vec<(String, String)> = Vec::new();
    let mut ok_count = 0usize;
    let mut err_count = 0usize;
    let mut dedup_count = 0usize;

    // Track rule names seen across ALL .yar files to deduplicate rules that
    // appear in multiple rule sets (e.g. YARA Forge full + Elastic rules).
    // Only the first occurrence of each rule name is compiled.
    let mut seen_rules: std::collections::HashSet<String> = std::collections::HashSet::new();

    for entry in WalkDir::new(rules_dir)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
    {
        let path = entry.path();

        // Accept both .yar and .yara extensions.
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "yar" && ext != "yara" {
            continue;
        }

        let source = match fs::read_to_string(path) {
            Ok(s) => s.replace("\r\n", "\n"),
            Err(e) => {
                warn!("cannot read rule file '{}': {}", path.display(), e);
                err_count += 1;
                continue;
            }
        };

        // Determine the source label for this file based on its path.
        let source_label = rule_source_label(rules_dir, path);

        // ── Fast path ─────────────────────────────────────────────────────
        {
            let mut t = Compiler::new();
            t.relaxed_re_syntax(true);
            if t.add_source(source.as_str()).is_ok() {
                let deduped_source = remove_seen_rules(source, &mut seen_rules, &mut dedup_count);
                ok_count += count_rules(&deduped_source);
                clean.push((deduped_source, source_label.clone()));
                continue;
            }
        }

        // ── Slow path: error-guided surgery ───────────────────────────────
        // Remove within-file duplicate rule names first (structural issue),
        // then iteratively remove whichever rule the compiler points to.
        let deduped = remove_duplicate_rules(&source);
        let removed_dupes = count_rules(&source).saturating_sub(count_rules(&deduped));
        if removed_dupes > 0 {
            log::debug!(
                "removed {} duplicate rules from '{}'",
                removed_dupes,
                path.display()
            );
        }

        let deduped_count = count_rules(&deduped);
        let (result_source, removed_incompat) =
            iterative_fix(deduped, path.display().to_string().as_str());

        let total_removed = removed_dupes + removed_incompat;
        err_count += total_removed;

        if total_removed > 0 {
            warn!(
                "{} rules removed from '{}' ({} duplicates, {} incompatible)",
                total_removed,
                path.display(),
                removed_dupes,
                removed_incompat
            );
        }

        if let Some(src) = result_source {
            let deduped_source = remove_seen_rules(src, &mut seen_rules, &mut dedup_count);
            ok_count += count_rules(&deduped_source);
            clean.push((deduped_source, source_label.clone()));
        } else {
            warn!("could not produce a compilable version of '{}'", path.display());
            err_count += deduped_count;
        }
    }

    if dedup_count > 0 {
        log::debug!(
            "{} duplicate rules removed across rule sets ({} unique rules loaded)",
            dedup_count, ok_count
        );
    }

    if ok_count == 0 {
        return Err(anyhow!(
            "no .yar/.yara rules compiled successfully from '{}' ({} errors). \
             Run with --sync to download fresh rules.",
            rules_dir.display(),
            err_count
        ));
    }

    if err_count > 0 {
        warn!(
            "{} rule(s) removed ({} loaded successfully)",
            err_count, ok_count
        );
    }

    // ── Final compilation on a single fresh compiler ──────────────────────
    let mut compiler = Compiler::new();
    compiler.relaxed_re_syntax(true);

    // Build a map of rule_identifier → source_label while compiling.
    // We extract rule names from each source block and tag them with
    // the file's label so callers can attribute matches to their origin.
    let mut source_map: HashMap<String, String> = HashMap::new();

    for (src, label) in &clean {
        if let Err(e) = compiler.add_source(src.as_str()) {
            warn!("unexpected final compile error: {}", e);
            continue;
        }
        // Tag every rule name in this source with its label.
        for line in src.lines() {
            let t = line.trim_start();
            for prefix in &[
                "private global rule ", "global private rule ",
                "private rule ", "global rule ", "rule ",
            ] {
                if t.starts_with(prefix) {
                    let name: String = t[prefix.len()..]
                        .split(|c: char| c.is_whitespace() || c == ':' || c == '{')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    if !name.is_empty() {
                        source_map.insert(name, label.clone());
                    }
                    break;
                }
            }
        }
    }

    let rules = compiler.build();
    Ok((rules, ok_count, source_map))
}

/// Iteratively compile `source`, removing whichever rule the compiler errors
/// on until the source compiles cleanly or the iteration limit is reached.
///
/// Each iteration creates exactly one throw-away compiler. When a rule is
/// removed the loop restarts from the updated source, so at most
/// `MAX_ITER` rules are removed before giving up.
///
/// Returns `(Some(clean_source), rules_removed)` on success,
/// `(None, rules_removed)` if the source still fails after max iterations.
fn iterative_fix(mut source: String, label: &str) -> (Option<String>, usize) {
    const MAX_ITER: usize = 200;
    let mut removed = 0usize;

    for _ in 0..MAX_ITER {
        let mut t = Compiler::new();
        t.relaxed_re_syntax(true);

        match t.add_source(source.as_str()) {
            Ok(_) => return (Some(source), removed),
            Err(e) => {
                let err_str = e.to_string();

                // Extract the line number from the error message.
                // yara-x formats errors as:  --> line:N:M
                let line_no = match parse_error_line(&err_str) {
                    Some(n) => n,
                    None => {
                        warn!("cannot parse line number from error for '{}': {}", label, err_str);
                        return (None, removed);
                    }
                };

                // Remove the rule block that contains the failing line and
                // loop back to recompile the updated source.
                match remove_rule_at_line(&source, line_no) {
                    Some(new_source) => {
                        log::debug!(
                            "removed rule at line {} in '{}': {}",
                            line_no, label,
                            first_line_of_error(&err_str)
                        );
                        source = new_source;
                        removed += 1;
                    }
                    None => {
                        warn!(
                            "cleaned source still fails for '{}': {}",
                            label, err_str
                        );
                        return (None, removed);
                    }
                }
            }
        }
    }

    warn!(
        "reached iteration limit cleaning '{}' ({} rules removed)",
        label, removed
    );
    (None, removed)
}

/// Parse the first line number from a yara-x error message.
/// Format: `  --> line:N:M`
fn parse_error_line(err: &str) -> Option<usize> {
    for part in err.split("line:") {
        let n: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(line) = n.parse::<usize>() {
            if line > 0 {
                return Some(line);
            }
        }
    }
    None
}

/// Return the first meaningful line of an error string for logging.
fn first_line_of_error(err: &str) -> &str {
    err.lines().next().unwrap_or(err)
}

/// Remove the rule block that contains line `line_no` (1-based) from `source`.
/// Returns the modified source, or `None` if no rule block could be identified.
fn remove_rule_at_line(source: &str, line_no: usize) -> Option<String> {
    let lines: Vec<&str> = source.lines().collect();
    if line_no == 0 || line_no > lines.len() {
        return None;
    }

    let rule_prefixes = [
        "private global rule ",
        "global private rule ",
        "private rule ",
        "global rule ",
        "rule ",
    ];

    // Walk backwards from line_no to find the start of the enclosing rule.
    let rule_start = (0..line_no)
        .rev()
        .find(|&i| {
            let t = lines[i].trim_start();
            rule_prefixes.iter().any(|p| t.starts_with(p))
        })?;

    // Walk forwards from rule_start to find the closing `}` (depth = 0).
    let mut depth: usize = 0;
    let mut rule_end = rule_start;
    let mut found_open = false;

    for (i, line) in lines.iter().enumerate().skip(rule_start) {
        let mut in_str = false;
        let mut escape_next = false;
        let mut chars = line.chars().peekable();
        while let Some(ch) = chars.next() {
            if escape_next { escape_next = false; continue; }
            match ch {
                '\\' if in_str => escape_next = true,
                '"' => in_str = !in_str,
                '/' if !in_str && chars.peek() == Some(&'/') => break,
                '{' if !in_str => { depth += 1; found_open = true; }
                '}' if !in_str && depth > 0 => {
                    depth -= 1;
                    if depth == 0 && found_open {
                        rule_end = i;
                        break;
                    }
                }
                _ => {}
            }
        }
        if depth == 0 && found_open { break; }
    }

    if !found_open {
        return None;
    }

    // Rebuild source without lines rule_start..=rule_end.
    let new_lines: Vec<&str> = lines
        .iter()
        .enumerate()
        .filter(|(i, _)| *i < rule_start || *i > rule_end)
        .map(|(_, l)| *l)
        .collect();

    Some(new_lines.join("\n"))
}

/// Remove duplicate rule names from a source, keeping the first occurrence.
fn remove_duplicate_rules(source: &str) -> String {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let lines: Vec<&str> = source.lines().collect();

    let rule_prefixes = [
        "private global rule ",
        "global private rule ",
        "private rule ",
        "global rule ",
        "rule ",
    ];

    // Find all rule blocks with their line ranges and names.
    let mut blocks: Vec<(usize, usize, String)> = Vec::new(); // (start, end, name)
    let mut i = 0;
    while i < lines.len() {
        let t = lines[i].trim_start();
        let is_rule = rule_prefixes.iter().any(|p| t.starts_with(p));
        if is_rule {
            // Extract name
            let rest = rule_prefixes.iter()
                .find(|p| t.starts_with(**p))
                .map(|p| &t[p.len()..])
                .unwrap_or("");
            let name: String = rest
                .split(|c: char| c.is_whitespace() || c == ':' || c == '{')
                .next()
                .unwrap_or("")
                .trim()
                .to_string();

            // Find end of this rule block
            let start = i;
            let mut depth = 0usize;
            let mut found_open = false;
            let mut end = i;
            for j in i..lines.len() {
                let mut in_str = false;
                let mut escape_next = false;
                let mut chars = lines[j].chars().peekable();
                while let Some(ch) = chars.next() {
                    if escape_next { escape_next = false; continue; }
                    match ch {
                        '\\' if in_str => escape_next = true,
                        '"' => in_str = !in_str,
                        '/' if !in_str && chars.peek() == Some(&'/') => break,
                        '{' if !in_str => { depth += 1; found_open = true; }
                        '}' if !in_str && depth > 0 => {
                            depth -= 1;
                            if depth == 0 && found_open { end = j; break; }
                        }
                        _ => {}
                    }
                }
                if depth == 0 && found_open { break; }
            }
            blocks.push((start, end, name));
            i = end + 1;
        } else {
            i += 1;
        }
    }

    // Collect line ranges to exclude (duplicate rule blocks).
    let mut excluded: std::collections::HashSet<usize> = std::collections::HashSet::new();
    for (start, end, name) in &blocks {
        if !seen.insert(name.clone()) {
            log::debug!("removing duplicate rule '{}'", name);
            for ln in *start..=*end {
                excluded.insert(ln);
            }
        }
    }

    if excluded.is_empty() {
        return source.to_string();
    }

    lines.iter()
        .enumerate()
        .filter(|(i, _)| !excluded.contains(i))
        .map(|(_, l)| *l)
        .collect::<Vec<_>>()
        .join("\n")
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Remove from `source` any rule whose name has already been seen across
/// previously processed files, updating `seen` with newly encountered names.
///
/// This is the cross-file deduplication pass (Option A).  It ensures that
/// when a user has multiple rule sets downloaded (e.g. YARA Forge full +
/// Elastic), each rule name is compiled at most once — the first `.yar` file
/// that defines it wins, subsequent occurrences are silently dropped.
fn remove_seen_rules(
    source: String,
    seen: &mut std::collections::HashSet<String>,
    dedup_count: &mut usize,
) -> String {
    let lines: Vec<&str> = source.lines().collect();

    let rule_prefixes = [
        "private global rule ",
        "global private rule ",
        "private rule ",
        "global rule ",
        "rule ",
    ];

    // Build a list of rule blocks with their line ranges.
    let mut blocks: Vec<(usize, usize, String)> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let t = lines[i].trim_start();
        if let Some(prefix) = rule_prefixes.iter().find(|p| t.starts_with(*p)) {
            let rest = &t[prefix.len()..];
            let name: String = rest
                .split(|c: char| c.is_whitespace() || c == ':' || c == '{')
                .next()
                .unwrap_or("")
                .trim()
                .to_string();

            let start = i;
            let mut depth = 0usize;
            let mut found_open = false;
            let mut end = i;

            for j in i..lines.len() {
                let mut in_str = false;
                let mut escape_next = false;
                let mut chars = lines[j].chars().peekable();
                while let Some(ch) = chars.next() {
                    if escape_next { escape_next = false; continue; }
                    match ch {
                        '\\' if in_str => escape_next = true,
                        '"' => in_str = !in_str,
                        '/' if !in_str && chars.peek() == Some(&'/') => break,
                        '{' if !in_str => { depth += 1; found_open = true; }
                        '}' if !in_str && depth > 0 => {
                            depth -= 1;
                            if depth == 0 && found_open { end = j; break; }
                        }
                        _ => {}
                    }
                }
                if depth == 0 && found_open { break; }
            }

            if !name.is_empty() {
                blocks.push((start, end, name));
            }
            i = end + 1;
        } else {
            i += 1;
        }
    }

    // Collect line indices to exclude (rules already seen in a previous file).
    let mut excluded: std::collections::HashSet<usize> = std::collections::HashSet::new();
    for (start, end, name) in &blocks {
        if !seen.insert(name.clone()) {
            for ln in *start..=*end {
                excluded.insert(ln);
            }
            *dedup_count += 1;
        }
    }

    if excluded.is_empty() {
        return source;
    }

    lines.iter()
        .enumerate()
        .filter(|(i, _)| !excluded.contains(i))
        .map(|(_, l)| *l)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Determine the human-readable source label for a YARA rule file.
///
/// - Files inside a `elastic/` subdirectory → `"Elastic Security"`
/// - Files named `yara-rules-*.yar` / `yara-rules-*.yara` (YARA Forge) → `"YARA Forge"`
/// - All other files                                   → `"Custom"`
fn rule_source_label(rules_dir: &Path, file_path: &Path) -> String {
    // Check if the file lives under a subdirectory named "elastic".
    if let Ok(rel) = file_path.strip_prefix(rules_dir) {
        let parts: Vec<_> = rel.components().collect();
        if parts.len() > 1 {
            if let Some(first) = parts[0].as_os_str().to_str() {
                if first.eq_ignore_ascii_case("elastic") {
                    return "Elastic Security".to_string();
                }
            }
        }
    }

    // Check for YARA Forge consolidated file naming convention.
    if let Some(fname) = file_path.file_name().and_then(|n| n.to_str()) {
        if fname.starts_with("yara-rules-") && (fname.ends_with(".yar") || fname.ends_with(".yara")) {
            return "YARA Forge".to_string();
        }
    }

    "Custom".to_string()
}

fn count_rules(source: &str) -> usize {
    source.lines().filter(|l| {
        let t = l.trim_start();
        t.starts_with("rule ")
            || t.starts_with("private rule ")
            || t.starts_with("global rule ")
            || t.starts_with("private global rule ")
            || t.starts_with("global private rule ")
    }).count()
}

// ─────────────────────────────────────────────────────────────────────────────
// Scanning
// ─────────────────────────────────────────────────────────────────────────────

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub title: String,
    pub identifier: String,
    pub metadata: HashMap<String, String>,
}

pub fn scan_bytes(rules: &Rules, data: &[u8]) -> Result<Vec<RuleMatch>> {
    let mut scanner = yara_x::Scanner::new(rules);
    let scan_results = scanner
        .scan(data)
        .map_err(|e| anyhow!("YARA scan error: {}", e))?;

    let mut matches = Vec::new();
    for rule in scan_results.matching_rules() {
        let identifier = rule.identifier().to_string();
        let metadata: HashMap<String, String> = rule
            .metadata()
            .map(|(k, v)| (k.to_string(), meta_value_to_string(v)))
            .collect();
        let title = metadata
            .get("name")
            .or_else(|| metadata.get("description"))
            .cloned()
            .unwrap_or_else(|| identifier.clone());
        matches.push(RuleMatch { title, identifier, metadata });
    }
    Ok(matches)
}

fn meta_value_to_string(v: yara_x::MetaValue) -> String {
    match v {
        yara_x::MetaValue::Integer(i) => i.to_string(),
        yara_x::MetaValue::Float(f)   => f.to_string(),
        yara_x::MetaValue::Bool(b)    => b.to_string(),
        yara_x::MetaValue::String(s)  => s.to_string(),
        yara_x::MetaValue::Bytes(b)   => hex::encode(b),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Rule compilation cache
// ─────────────────────────────────────────────────────────────────────────────

/// Load and compile rules, using a binary cache when possible.
///
/// The cache is keyed by a SHA-256 hash of all `.yar` file paths, sizes, and
/// modification times. If the cache file exists and its key matches the current
/// state of the rules directory, the compiled rules are deserialised directly —
/// skipping the 15–30 second compilation step on repeat runs.
///
/// Cache files live in `<rules_dir>/.cache/` and are named by their key hash.
/// Stale cache files (wrong key) are deleted and recompiled automatically.
pub fn load_rules_cached(
    rules_dir: &Path,
) -> anyhow::Result<(Rules, usize, HashMap<String, String>)> {
    let cache_dir = rules_dir.join(".cache");
    let cache_key = compute_rules_cache_key(rules_dir)?;
    let cache_path = cache_dir.join(format!("{}.bin", cache_key));

    // ── Try loading from cache ─────────────────────────────────────────────
    if cache_path.exists() {
        match try_load_cache(&cache_path) {
            Ok(result) => {
                log::info!("loaded compiled rules from cache ({})", cache_path.display());
                return Ok(result);
            }
            Err(e) => {
                log::warn!("cache load failed, recompiling: {}", e);
                let _ = std::fs::remove_file(&cache_path);
                let _ = std::fs::remove_file(cache_path.with_extension("json"));
            }
        }
    }

    // ── Compile from source and save cache ────────────────────────────────
    let result = load_rules(rules_dir)?;

    let _ = std::fs::create_dir_all(&cache_dir);
    match result.0.serialize() {
        Ok(bytes) => {
            // Write compiled binary.
            if let Err(e) = std::fs::write(&cache_path, &bytes) {
                log::warn!("could not write rules cache: {}", e);
            } else {
                // Write JSON sidecar (source_map + count) so cache hits never
                // need to recompile just to rebuild the source attribution map.
                let sidecar = CacheSidecar {
                    count:      result.1,
                    source_map: result.2.clone(),
                };
                let json_path = cache_path.with_extension("json");
                match serde_json::to_vec(&sidecar) {
                    Ok(json) => {
                        if let Err(e) = std::fs::write(&json_path, &json) {
                            log::warn!("could not write cache sidecar: {}", e);
                        }
                    }
                    Err(e) => log::warn!("could not serialise cache sidecar: {}", e),
                }

                log::info!(
                    "wrote compiled rules cache ({} KB) to {}",
                    bytes.len() / 1024,
                    cache_path.display()
                );
                prune_stale_cache(&cache_dir, &cache_key);
            }
        }
        Err(e) => {
            log::warn!("could not serialise compiled rules for caching: {}", e);
        }
    }

    Ok(result)
}

/// Attempt to deserialise compiled rules from `cache_path`.
/// Also loads the JSON sidecar (`<key>.json`) for the source_map and count.
/// No recompilation happens — this is the fast path.
fn try_load_cache(
    cache_path: &Path,
) -> anyhow::Result<(Rules, usize, HashMap<String, String>)> {
    let bytes = std::fs::read(cache_path)?;
    let rules = Rules::deserialize(&bytes)
        .map_err(|e| anyhow::anyhow!("deserialise error: {}", e))?;

    // Load the JSON sidecar written alongside the .bin at compilation time.
    let json_path = cache_path.with_extension("json");
    let json_bytes = std::fs::read(&json_path)
        .map_err(|e| anyhow::anyhow!("missing cache sidecar '{}': {}", json_path.display(), e))?;

    let sidecar: CacheSidecar = serde_json::from_slice(&json_bytes)
        .map_err(|e| anyhow::anyhow!("corrupt cache sidecar: {}", e))?;

    Ok((rules, sidecar.count, sidecar.source_map))
}

/// Data stored in the `.json` sidecar file alongside each `.bin` cache entry.
#[derive(serde::Serialize, serde::Deserialize)]
struct CacheSidecar {
    count:      usize,
    source_map: HashMap<String, String>,
}

/// Compute a stable cache key from the set of all `.yar` files in `rules_dir`.
///
/// The key is the lowercase hex SHA-256 of the concatenated
/// `<relative_path>\0<size>\0<mtime_secs>\0` for every `.yar` file,
/// sorted by relative path for determinism.
fn compute_rules_cache_key(rules_dir: &Path) -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};

    let mut entries: Vec<(String, u64, u64)> = Vec::new(); // (rel_path, size, mtime_secs)

    for entry in WalkDir::new(rules_dir)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let ext = e.path().extension().and_then(|s| s.to_str()).unwrap_or("");
            ext == "yar" || ext == "yara"
        })
    {
        let path = entry.path();
        let rel = path.strip_prefix(rules_dir)
            .unwrap_or(path)
            .to_string_lossy()
            .into_owned();
        let meta = path.metadata().unwrap_or_else(|_| entry.metadata().unwrap());
        let size = meta.len();
        let mtime = meta.modified()
            .map(|t| t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs())
            .unwrap_or(0);
        entries.push((rel, size, mtime));
    }

    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut hasher = Sha256::new();
    for (rel, size, mtime) in &entries {
        hasher.update(rel.as_bytes());
        hasher.update(b"\0");
        hasher.update(size.to_le_bytes());
        hasher.update(b"\0");
        hasher.update(mtime.to_le_bytes());
        hasher.update(b"\0");
    }

    Ok(hex::encode(hasher.finalize()))
}

/// Delete all `.bin` and `.json` files in `cache_dir` whose stem does not match `current_key`.
fn prune_stale_cache(cache_dir: &Path, current_key: &str) {
    if let Ok(rd) = std::fs::read_dir(cache_dir) {
        for entry in rd.filter_map(|e| e.ok()) {
            let p = entry.path();
            let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext == "bin" || ext == "json" {
                if p.file_stem().and_then(|s| s.to_str()) != Some(current_key) {
                    let _ = std::fs::remove_file(&p);
                    log::debug!("pruned stale cache file: {}", p.display());
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Hash allowlist
// ─────────────────────────────────────────────────────────────────────────────

/// Load a SHA-256 hash allowlist from a plain-text file.
///
/// Each non-empty, non-comment line (lines beginning with `#` are skipped)
/// is treated as a lowercase hex SHA-256 digest. Hashes are normalised to
/// lowercase so comparisons are case-insensitive.
pub fn load_allowlist(path: &Path) -> anyhow::Result<std::collections::HashSet<String>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read allowlist '{}': {}", path.display(), e))?;

    let mut set = std::collections::HashSet::new();
    let mut invalid = 0usize;

    for (lineno, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Validate: must be exactly 64 lowercase hex chars.
        let lower = trimmed.to_ascii_lowercase();
        if lower.len() == 64 && lower.chars().all(|c| c.is_ascii_hexdigit()) {
            set.insert(lower);
        } else {
            log::warn!("allowlist line {}: '{}' is not a valid SHA-256 hash, skipped",
                lineno + 1, trimmed);
            invalid += 1;
        }
    }

    if invalid > 0 {
        log::warn!("{} invalid allowlist entries skipped", invalid);
    }

    log::info!("loaded {} hashes from allowlist '{}'", set.len(), path.display());
    Ok(set)
}

// ─────────────────────────────────────────────────────────────────────────────
// Rule name filtering
// ─────────────────────────────────────────────────────────────────────────────

/// Filter a source_map by include/exclude glob patterns.
///
/// - If `include` is non-empty, only rules whose identifier matches at least
///   one include pattern are kept.
/// - Rules whose identifier matches any exclude pattern are removed.
/// - Matching is case-insensitive.
/// - Glob syntax: `*` matches any sequence of characters (excluding `.`
///   and `:`), `?` matches a single character.
///
/// Returns the filtered map. Callers should pass this to `scan_bytes`'s
/// result-checking step so unmatched rules are simply not reported.
pub fn filter_source_map(
    source_map: HashMap<String, String>,
    include: &[String],
    exclude: &[String],
) -> HashMap<String, String> {
    if include.is_empty() && exclude.is_empty() {
        return source_map;
    }

    source_map.into_iter().filter(|(name, _)| {
        let lower = name.to_ascii_lowercase();

        // Exclude takes priority.
        if exclude.iter().any(|pat| glob_match(&pat.to_ascii_lowercase(), &lower)) {
            return false;
        }

        // Include filter: must match at least one pattern if any are given.
        if !include.is_empty() {
            return include.iter().any(|pat| glob_match(&pat.to_ascii_lowercase(), &lower));
        }

        true
    }).collect()
}

/// Minimal glob matcher supporting `*` (any chars) and `?` (single char).
/// Case-insensitive (caller should lowercase both before calling).
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    glob_match_inner(&p, &t)
}

fn glob_match_inner(p: &[char], t: &[char]) -> bool {
    match (p.first(), t.first()) {
        (None, None)        => true,
        (Some(&'*'), _) => {
            // '*' can match zero or more characters.
            glob_match_inner(&p[1..], t)
                || (!t.is_empty() && glob_match_inner(p, &t[1..]))
        }
        (Some(&'?'), Some(_)) => glob_match_inner(&p[1..], &t[1..]),
        (Some(pc), Some(tc)) if pc == tc => glob_match_inner(&p[1..], &t[1..]),
        _ => false,
    }
}
