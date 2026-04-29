//! yscanfs — YARA scanner for forensic disk images.
//! https://github.com/jw4n6/yscanfs
//!
//! # Usage
//!
//! ```text
//! yscanfs --sync                              # download YARA Forge full rules
//! yscanfs -f image.E01                        # scan EWF image
//! yscanfs -d /cases/images/                   # scan all images recursively
//! yscanfs -f image.E01 --vss                  # scan live + all VSS snapshots
//! yscanfs -f image.E01 --list-vss             # list VSS snapshots and exit
//! yscanfs -f image.E01 -F json                # JSON output
//! yscanfs -f image.E01 --allowlist nsrl.txt   # skip known-good hashes
//! yscanfs -f image.E01 --include-rule "Win*"  # only run matching rules
//! yscanfs -f image.E01 --exclude-rule "PUP*"  # skip matching rules
//! yscanfs -f image.E01 -q                     # quiet mode for scripting
//! yscanfs -f image.E01 --unique-files          # deduplicate paths per rule
//! ```
mod cli;
mod disk;
mod fs_walker;
mod output;
mod rules;
mod scanner;
mod vss;

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use clap::Parser;
use colored::Colorize;
use comfy_table::{Attribute, Cell, Color, Table};
use indicatif::{ProgressBar, ProgressStyle};
use simplelog::{CombinedLogger, Config, LevelFilter, TermLogger, TerminalMode, WriteLogger};

use cli::{Args, OutputFormat};
use disk::{open_image, PartitionReader};
use fs_walker::{walk_ntfs, walk_ext4};
use output::{detect_type, parse_pe_timestamp, pe_imported_dlls, pe_pdb_path,
             sha256_hex, write_csv, write_json, deduplicate_results, ScanResult};
use scanner::{load_rules_cached, load_allowlist, filter_source_map, scan_bytes};
use yara_x::Rules;

// ─────────────────────────────────────────────────────────────────────────────
// Platform-aware display symbols
//
// Windows PowerShell's default font (Consolas) has no glyphs for braille
// block characters or many Unicode bullets. We detect Windows at compile time
// and fall back to ASCII-safe alternatives so output is always readable.
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
mod sym {
    pub const SPINNER_CHARS: &str = r"-\|/ ";
    pub const OK:            &str = "[+]";
    pub const INFO:          &str = "[i]";
    pub const BULLET:        &str = "*";
    pub const WARN_BULLET:   &str = "!";
    pub const ARROW:         &str = "->";
}

#[cfg(not(target_os = "windows"))]
mod sym {
    pub const SPINNER_CHARS: &str = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ ";
    pub const OK:            &str = "✓";
    pub const INFO:          &str = "i";
    pub const BULLET:        &str = "•";
    pub const WARN_BULLET:   &str = "•";
    pub const ARROW:         &str = "→";
}

// ─────────────────────────────────────────────────────────────────────────────
// Macro: print unless --quiet is set
// ─────────────────────────────────────────────────────────────────────────────

macro_rules! qprintln {
    ($quiet:expr, $($arg:tt)*) => {
        if !$quiet { println!($($arg)*); }
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────

fn main() {
    let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();
    let stem      = format!("yscanfs_{}", timestamp);

    let logs_dir = PathBuf::from("logs");
    if let Err(e) = std::fs::create_dir_all(&logs_dir) {
        eprintln!("Error: cannot create logs directory: {}", e);
        std::process::exit(1);
    }
    let log_path = logs_dir.join(format!("{}.log", stem));

    let log_file = match File::create(&log_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error: cannot create log file '{}': {}", log_path.display(), e);
            std::process::exit(1);
        }
    };

    let debug_mode = std::env::args().any(|a| a == "-D" || a == "--debug");

    let mut loggers: Vec<Box<dyn simplelog::SharedLogger>> = vec![
        TermLogger::new(LevelFilter::Error, Config::default(), TerminalMode::Stderr,
            simplelog::ColorChoice::Auto),
        WriteLogger::new(LevelFilter::Warn, Config::default(), log_file),
    ];

    let debug_log_path = logs_dir.join(format!("{}_debug.log", stem));
    if debug_mode {
        match File::create(&debug_log_path) {
            Ok(f) => loggers.push(WriteLogger::new(LevelFilter::Debug, Config::default(), f)),
            Err(e) => eprintln!("Warning: cannot create debug log file: {}", e),
        }
    }

    CombinedLogger::init(loggers).expect("logger init failed");

    if let Err(e) = run(stem, log_path, debug_mode, debug_log_path) {
        eprintln!("{} {}", "Error:".red().bold(), e);
        std::process::exit(1);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Main pipeline
// ─────────────────────────────────────────────────────────────────────────────

fn run(
    stem: String,
    log_path: PathBuf,
    debug_mode: bool,
    debug_log_path: PathBuf,
) -> anyhow::Result<()> {
    let args = Args::parse();
    let quiet = args.quiet;

    // ── Parse output format ───────────────────────────────────────────────
    let fmt = OutputFormat::from_str(&args.output_format)?;

    // ── Resolve output path ───────────────────────────────────────────────
    let output_path = args.output.clone().unwrap_or_else(|| {
        PathBuf::from(format!("{}.{}", stem, fmt.extension()))
    });

    // ── Optional rules sync ───────────────────────────────────────────────
    if let Some(ref tier) = args.sync {
        let is_elastic = tier.eq_ignore_ascii_case("elastic");

        if is_elastic && !args.accept_elastic_license {
            return Err(anyhow::anyhow!(
                "Elastic Security rules require license acceptance.\n\
                 Add --accept-elastic-license to confirm you accept the\n\
                 Elastic License 2.0: https://www.elastic.co/licensing/elastic-license"
            ));
        }

        if !is_elastic {
            let ruleset = rules::RuleSet::from_str(tier)?;
            qprintln!(quiet, "{}", format!("Syncing YARA Forge {} rules…", ruleset.name()).cyan().bold());
            rules::sync_rules(&args.rules, ruleset)?;
        }

        if is_elastic || args.accept_elastic_license {
            qprintln!(quiet, "{}", "Syncing Elastic Security rules…".cyan().bold());
            qprintln!(quiet, "  {} Elastic License 2.0 accepted via --accept-elastic-license", sym::INFO.cyan());
            rules::sync_elastic_rules(&args.rules)?;
        }

        if args.file.is_none() && args.dir.is_none() {
            return Ok(());
        }
    } else if args.accept_elastic_license {
        qprintln!(quiet, "{}", "Syncing Elastic Security rules…".cyan().bold());
        qprintln!(quiet, "  {} Elastic License 2.0 accepted", sym::INFO.cyan());
        rules::sync_elastic_rules(&args.rules)?;
        if args.file.is_none() && args.dir.is_none() {
            return Ok(());
        }
    }

    // ── Max file size ─────────────────────────────────────────────────────
    let max_size = args.max_size * 1_048_576;

    // ── List VSS snapshots and exit ───────────────────────────────────────
    if args.list_vss {
        let image_paths = collect_image_paths(&args)?;
        for image_path in &image_paths {
            let image_name = image_path.file_name()
                .and_then(|n| n.to_str()).unwrap_or("unknown");
            println!("{} {}", "VSS snapshots in:".cyan().bold(), image_name);
            match vss::list_snapshots(image_path) {
                Ok(snapshots) if snapshots.is_empty() => {
                    println!("  No VSS snapshots found.");
                }
                Ok(snapshots) => {
                    for (part_idx, snap) in &snapshots {
                        println!(
                            "  {} Partition {}  Snapshot #{:02}  {}  ({} GB)",
                            sym::OK.green().bold(),
                            part_idx + 1,
                            snap.index,
                            snap.created.format("%Y-%m-%d %H:%M:%S UTC"),
                            snap.volume_size / (1 << 30),
                        );
                    }
                    println!("  {} total snapshot(s)", snapshots.len());
                }
                Err(e) => {
                    eprintln!("  Error: {}", e);
                }
            }
        }
        return Ok(());
    }

    // ── Load allowlist ────────────────────────────────────────────────────
    let allowlist: HashSet<String> = if let Some(ref al_path) = args.allowlist {
        let set = load_allowlist(al_path)?;
        qprintln!(quiet, "  {} Allowlist: {} hashes loaded from '{}'",
            sym::OK.green().bold(), set.len(), al_path.display());
        set
    } else {
        HashSet::new()
    };
    let allowlist = Arc::new(allowlist);

    // ── Load YARA rules (with compilation cache) ───────────────────────────
    qprintln!(quiet, "{}", "Loading YARA rules…".cyan().bold());
    let rule_load_start = Instant::now();
    let (rules, rule_count, source_map) = load_rules_cached(&args.rules)?;
    let rules      = Arc::new(rules);
    // Apply --include-rule / --exclude-rule filters to the source map.
    // Rules not in the filtered map will still be scanned but their matches
    // will be silently dropped in the worker, giving the same effect as not
    // loading them without requiring recompilation.
    let source_map = filter_source_map(source_map, &args.include_rule, &args.exclude_rule);
    if !args.include_rule.is_empty() || !args.exclude_rule.is_empty() {
        qprintln!(quiet, "  {} Rule filter: {} rules active after include/exclude",
            sym::INFO.cyan(), source_map.len());
    }
    let source_map = Arc::new(source_map);
    let load_elapsed = rule_load_start.elapsed();
    qprintln!(quiet,
        "  {} Loaded {} rule(s) in {:.1}s",
        sym::OK.green().bold(),
        rule_count,
        load_elapsed.as_secs_f64()
    );

    // ── Collect image paths ───────────────────────────────────────────────
    qprintln!(quiet, "{}", "Discovering disk images…".cyan().bold());
    let image_paths = collect_image_paths(&args)?;

    // ── Spinner ───────────────────────────────────────────────────────────
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("  {spinner:.cyan} {msg}")
            .unwrap()
            .tick_chars(sym::SPINNER_CHARS),
    );
    if quiet { pb.set_draw_target(indicatif::ProgressDrawTarget::hidden()); }

    let mut all_results: Vec<ScanResult> = Vec::new();
    let mut total_files: u64 = 0;
    let mut image_errors: Vec<(String, String)> = Vec::new();
    let scan_start = Instant::now();

    // ── Process each image ────────────────────────────────────────────────
    for (img_idx, image_path) in image_paths.iter().enumerate() {
        let image_name = image_path
            .file_name().and_then(|n| n.to_str())
            .unwrap_or("unknown").to_string();

        pb.disable_steady_tick();
        if image_paths.len() > 1 {
            qprintln!(quiet, "\n{} {}/{}  {}",
                "Scanning:".cyan().bold(), img_idx + 1, image_paths.len(), image_name);
        } else {
            qprintln!(quiet, "{} {}", "Scanning:".cyan().bold(), image_name);
        }
        pb.enable_steady_tick(Duration::from_millis(80));

        match scan_image(
            image_path, &image_name, max_size,
            &rules, &source_map, &allowlist, args.vss, &pb,
        ) {
            Ok((results, files)) => {
                total_files += files;
                all_results.extend(results);
            }
            Err(e) => {
                let msg = format!("{}", e);
                log::warn!("image '{}' failed: {}", image_name, msg);
                image_errors.push((image_name, msg));
            }
        }
    }

    pb.finish_and_clear();

    // ── Apply rule name filter to results ─────────────────────────────────
    // source_map was already filtered by include/exclude patterns above.
    // Drop results whose identifier is absent from the filtered map
    // (custom rules without a source_map entry are always kept).
    let all_results: Vec<ScanResult> = if !args.include_rule.is_empty() || !args.exclude_rule.is_empty() {
        all_results.into_iter()
            .filter(|r| r.rule_source == "Custom"
                || source_map.contains_key(&r.rule_identifier))
            .collect()
    } else {
        all_results
    };

    // ── Deduplicate by (rule, SHA-256) if requested ───────────────────────
    let (all_results, dedup_msg) = if args.unique_files {
        let before = all_results.len();
        let deduped = deduplicate_results(all_results);
        let after = deduped.len();
        let msg = if before != after {
            Some(format!(
                "  {} {} duplicate path(s) consolidated ({} {} {} unique rows)",
                sym::OK.green().bold(),
                before - after,
                before,
                sym::ARROW,
                after,
            ))
        } else {
            None
        };
        (deduped, msg)
    } else {
        (all_results, None)
    };

    // ── Write output ──────────────────────────────────────────────────────
    let out_file = File::create(&output_path)
        .map_err(|e| anyhow::anyhow!("cannot create '{}': {}", output_path.display(), e))?;

    match fmt {
        OutputFormat::Csv  => write_csv(out_file, &all_results)?,
        OutputFormat::Json => write_json(out_file, &all_results, total_files)?,
    }

    // In quiet mode, print only the output path (for scripting).
    if quiet {
        println!("{}", output_path.display());
        return Ok(());
    }

    println!("  {} Results  {} '{}'", sym::OK.green().bold(), sym::ARROW, output_path.display());
    println!("  {} Scan log {} '{}'", sym::OK.green().bold(), sym::ARROW, log_path.display());
    if debug_mode {
        println!("  {} Debug log {} '{}'", sym::OK.green().bold(), sym::ARROW, debug_log_path.display());
    }
    if let Some(msg) = dedup_msg {
        println!("{}", msg);
    }

    print_summary(&all_results, total_files, scan_start.elapsed(), &image_errors);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-image scan
// ─────────────────────────────────────────────────────────────────────────────

fn scan_image(
    image_path: &Path,
    image_name: &str,
    max_size: u64,
    rules: &Arc<Rules>,
    source_map: &Arc<HashMap<String, String>>,
    allowlist: &Arc<HashSet<String>>,
    vss_enabled: bool,
    pb: &ProgressBar,
) -> anyhow::Result<(Vec<ScanResult>, u64)> {
    let partitions = disk::find_partitions(image_path)?;
    if partitions.is_empty() {
        return Err(anyhow::anyhow!(
            "no supported partitions found in '{}' (NTFS and EXT4 are supported)",
            image_name
        ));
    }

    let num_workers = std::thread::available_parallelism()
        .map(|n| n.get()).unwrap_or(4).min(8);

    let (file_tx, file_rx) = std::sync::mpsc::sync_channel::<fs_walker::FileEntry>(num_workers * 4);
    let (result_tx, result_rx) = std::sync::mpsc::channel::<ScanResult>();
    let file_rx = Arc::new(std::sync::Mutex::new(file_rx));

    // ── Spawn YARA workers ────────────────────────────────────────────────
    let mut worker_handles = Vec::with_capacity(num_workers);
    for _ in 0..num_workers {
        let file_rx    = Arc::clone(&file_rx);
        let result_tx  = result_tx.clone();
        let rules      = Arc::clone(rules);
        let source_map = Arc::clone(source_map);
        let allowlist  = Arc::clone(allowlist);
        let image_name = image_name.to_string();

        worker_handles.push(std::thread::spawn(move || {
            loop {
                let entry = match file_rx.lock().unwrap().recv() {
                    Ok(e) => e, Err(_) => break,
                };

                // ── Allowlist check ────────────────────────────────────────
                // Compute the hash first; skip the YARA scan entirely if the
                // file is in the allowlist. This avoids wasting YARA engine
                // time on known-good system files.
                let sha256 = sha256_hex(&entry.data);
                if !allowlist.is_empty() && allowlist.contains(&sha256) {
                    log::debug!("allowlist: skipping {} ({})", entry.path, sha256);
                    continue;
                }

                // ── YARA scan ──────────────────────────────────────────────
                let matches = match scan_bytes(&rules, &entry.data) {
                    Ok(m) => m,
                    Err(e) => {
                        log::warn!("YARA scan error for '{}': {}", entry.path, e);
                        continue;
                    }
                };
                if matches.is_empty() { continue; }

                let file_type       = detect_type(&entry.data, &entry.path);
                let pe_compile_time = parse_pe_timestamp(&entry.data);
                let pe_imports = if file_type == ".exe" || file_type == ".dll" {
                    pe_imported_dlls(&entry.data).join(",")
                } else {
                    String::new()
                };
                let pdb_path = if file_type == ".exe" || file_type == ".dll" {
                    pe_pdb_path(&entry.data).unwrap_or_default()
                } else {
                    String::new()
                };

                for m in matches {
                    let rule_source = source_map.get(&m.identifier)
                        .cloned().unwrap_or_else(|| "Custom".to_string());
                    let _ = result_tx.send(ScanResult {
                        source_image: image_name.clone(),
                        timestamp: entry.creation_time,
                        pe_compile_time,
                        rule_title: m.title,
                        rule_identifier: m.identifier,
                        rule_source,
                        file_path: entry.path.clone(),
                        sha256: sha256.clone(),
                        file_type: file_type.clone(),
                        pe_imports: pe_imports.clone(),
                        pdb_path: pdb_path.clone(),
                    });
                }
            }
        }));
    }
    drop(result_tx);

    // ── Producer: walk filesystem ─────────────────────────────────────────
    let mut total_files: u64 = 0;
    // Track files and time for scan rate display.
    let walk_start = Instant::now();

    for partition in partitions.iter() {
        let fs_label = match partition.filesystem {
            disk::FilesystemType::Ntfs => "NTFS",
            disk::FilesystemType::Ext4 => "EXT4",
        };

        let img = open_image(image_path)?;

        match partition.filesystem {
            disk::FilesystemType::Ntfs => {
                let mut reader = PartitionReader::new(img, partition.offset, partition.size)
                    .map_err(|e| anyhow::anyhow!("PartitionReader: {}", e))?;

                // Run inside catch_unwind: ntfs crate v0.4.0 panics with an
                // internal unreachable!() on compressed/corrupt NTFS attribute
                // lists instead of returning an error. Catching the panic keeps
                // the scan alive so all other files and images are still processed.
                let file_tx_c = file_tx.clone();
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    walk_ntfs(&mut reader, max_size, pb, |entry| {
                        total_files += 1;
                        update_spinner(pb, total_files, &walk_start, "NTFS");
                        if file_tx_c.send(entry).is_err() {
                            log::warn!("file channel closed unexpectedly");
                        }
                    })
                }));
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        log::warn!("NTFS walk error in '{}': {}", image_name, e);
                    }
                    Err(_) => {
                        log::warn!(
                            "NTFS walk panicked in '{}' — likely a compressed or corrupt \
                             NTFS attribute list (ntfs crate v0.4.0 limitation). \
                             Files scanned before the panic are preserved in results.",
                            image_name
                        );
                        pb.set_message(format!(
                            "Warning: partial NTFS walk in {} — see log for details",
                            image_name
                        ));
                    }
                }
            }
            disk::FilesystemType::Ext4 => {
                let reader = PartitionReader::new(img, partition.offset, partition.size)
                    .map_err(|e| anyhow::anyhow!("PartitionReader: {}", e))?;
                walk_ext4(reader, max_size, pb, |entry| {
                    total_files += 1;
                    update_spinner(pb, total_files, &walk_start, fs_label);
                    if file_tx.send(entry).is_err() {
                        log::warn!("file channel closed unexpectedly");
                    }
                })?;
            }
        }
    }

    // ── VSS snapshot scanning ─────────────────────────────────────────────
    if vss_enabled {
        for partition in partitions.iter() {
            if partition.filesystem != disk::FilesystemType::Ntfs {
                continue;
            }
            let file_tx_vss = file_tx.clone();
            let image_name_vss = image_name.to_string();
            let allowlist_vss  = Arc::clone(allowlist);

            match vss::walk_vss_snapshots(
                image_path, partition.offset, partition.size,
                max_size, pb,
                |mut entry, snap| {
                    total_files += 1;
                    // Label the source so results are clearly attributed.
                    entry.path = format!(
                        "[VSS#{} {}] {}",
                        snap.index,
                        snap.created.format("%Y-%m-%d"),
                        entry.path
                    );
                    update_spinner(pb, total_files, &walk_start, "VSS");
                    if file_tx_vss.send(entry).is_err() {
                        log::warn!("file channel closed during VSS walk");
                    }
                },
            ) {
                Ok(snaps) => {
                    if !snaps.is_empty() {
                        log::info!("{} VSS snapshot(s) scanned in '{}'", snaps.len(), image_name_vss);
                    }
                }
                Err(e) => log::warn!("VSS scan error in '{}': {}", image_name_vss, e),
            }
            let _ = allowlist_vss; // used via closure capture
        }
    }

    drop(file_tx);

    let mut panicked = 0usize;
    for handle in worker_handles {
        if handle.join().is_err() { panicked += 1; }
    }
    if panicked > 0 {
        log::warn!(
            "{} YARA worker thread(s) panicked in '{}'. Check debug log.",
            panicked, image_name
        );
    }

    Ok((result_rx.iter().collect(), total_files))
}

/// Update the spinner message with live file count, scan rate, and elapsed time.
/// Called on every file so updates are frequent but cheap (just string formatting).
#[inline]
fn update_spinner(pb: &ProgressBar, total_files: u64, start: &Instant, fs_label: &str) {
    // Only update the message every 100 files to avoid locking overhead.
    if total_files % 100 != 0 { return; }

    let elapsed = start.elapsed().as_secs_f64();
    let rate = if elapsed > 0.0 { (total_files as f64 / elapsed) as u64 } else { 0 };

    let elapsed_str = format_duration(start.elapsed());

    pb.set_message(format!(
        "{} files  {} {}/s  {} {}",
        total_files,
        sym::BULLET,
        rate,
        sym::BULLET,
        elapsed_str,
    ));

    // Suppress the FS label from being the only thing shown at the very start.
    let _ = fs_label; // label already shown in the "Scanning X partition…" header
}

fn format_duration(d: Duration) -> String {
    let s = d.as_secs();
    if s < 60 { format!("{}s", s) }
    else       { format!("{}m {}s", s / 60, s % 60) }
}

// ─────────────────────────────────────────────────────────────────────────────
// Image path collection
// ─────────────────────────────────────────────────────────────────────────────

fn collect_image_paths(args: &Args) -> anyhow::Result<Vec<PathBuf>> {
    let mut paths: Vec<PathBuf> = Vec::new();

    if let Some(ref f) = args.file {
        if !f.exists() {
            return Err(anyhow::anyhow!("file not found: '{}'", f.display()));
        }
        let fmt = disk::ImageFormat::detect(f).ok();
        let fmt_label = match fmt {
            Some(disk::ImageFormat::Ewf)      => " (EWF)",
            Some(disk::ImageFormat::Raw)      => " (raw)",
            Some(disk::ImageFormat::SplitRaw) => " (split raw)",
            None => "",
        };
        println!(
            "  {} Found '{}'{}\n",
            sym::OK.green().bold(),
            f.file_name().and_then(|n| n.to_str()).unwrap_or("unknown"),
            fmt_label
        );
        paths.push(f.clone());
    }

    if let Some(ref dir) = args.dir {
        if !dir.is_dir() {
            return Err(anyhow::anyhow!("'{}' is not a directory", dir.display()));
        }

        let mut found = walkdir::WalkDir::new(dir)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.path().to_path_buf())
            .filter(|p| {
                p.extension().and_then(|e| e.to_str())
                    .map(|ext| {
                        let el = ext.to_ascii_lowercase();
                        disk::ImageFormat::all_extensions().iter().any(|&e| e == el)
                        || {
                            let b = el.as_bytes();
                            (el.len() == 3 && b[0] == b'e'
                                && b[1].is_ascii_alphabetic()
                                && b[2].is_ascii_alphabetic())
                            || el == "001"
                        }
                    })
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();

        found.sort();

        if found.is_empty() {
            return Err(anyhow::anyhow!(
                "no supported disk images found in '{}'. \
                 Supported: .E01 (EWF), .raw/.dd/.img/.bin (raw), .001 (split raw)",
                dir.display()
            ));
        }

        println!(
            "  {} Found {} image(s) in '{}'\n",
            sym::OK.green().bold(),
            found.len(),
            dir.display()
        );
        paths.extend(found);
    }

    if paths.is_empty() {
        return Err(anyhow::anyhow!(
            "no image specified. Use -f <FILE> for a single image or -d <DIR> for a directory."
        ));
    }
    Ok(paths)
}

// ─────────────────────────────────────────────────────────────────────────────
// Summary display
// ─────────────────────────────────────────────────────────────────────────────

fn print_summary(
    results: &[ScanResult],
    total_files: u64,
    elapsed: Duration,
    image_errors: &[(String, String)],
) {
    let elapsed_str = format_duration(elapsed);
    let rate = if elapsed.as_secs_f64() > 0.0 {
        (total_files as f64 / elapsed.as_secs_f64()) as u64
    } else { 0 };

    println!();
    println!("{}", "─────────────────────────────────────────".bright_black());
    println!("  {} Files scanned : {}  ({}/s)",
        sym::BULLET.cyan(), total_files.to_string().bold(), rate);
    println!("  {} Rules matched  : {}",
        sym::BULLET.cyan(),
        {
            let unique: std::collections::HashSet<&str> =
                results.iter().map(|r| r.rule_title.as_str()).collect();
            unique.len().to_string().bold()
        });
    println!("  {} Total hits     : {}", sym::BULLET.cyan(), results.len().to_string().bold());
    println!("  {} Time elapsed   : {}", sym::BULLET.cyan(), elapsed_str.bold());
    if !image_errors.is_empty() {
        println!("  {} Image errors   : {}  (see log for details)",
            sym::WARN_BULLET.yellow(), image_errors.len().to_string().yellow().bold());
    }
    println!("{}", "─────────────────────────────────────────".bright_black());

    if results.is_empty() && image_errors.is_empty() {
        println!("  {}", "No YARA matches found.".green().bold());
        println!();
        return;
    }

    if !results.is_empty() {
        let mut rule_hits: HashMap<&str, usize> = HashMap::new();
        let mut rule_files: HashMap<&str, std::collections::HashSet<&str>> = HashMap::new();
        for r in results {
            *rule_hits.entry(r.rule_title.as_str()).or_insert(0) += 1;
            rule_files.entry(r.rule_title.as_str()).or_default().insert(r.file_path.as_str());
        }
        let mut sorted: Vec<(&str, usize)> = rule_hits.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));

        let mut table = Table::new();
        table.set_header(vec![
            Cell::new("Rule").add_attribute(Attribute::Bold),
            Cell::new("Hits").add_attribute(Attribute::Bold).fg(Color::Yellow),
            Cell::new("Files").add_attribute(Attribute::Bold).fg(Color::Cyan),
        ]);
        for (rule, hits) in &sorted {
            let files = rule_files.get(rule).map(|s| s.len()).unwrap_or(0);
            table.add_row(vec![
                Cell::new(rule),
                Cell::new(hits.to_string()).fg(Color::Yellow),
                Cell::new(files.to_string()).fg(Color::Cyan),
            ]);
        }
        println!();
        println!("{}", table);
    }

    if !image_errors.is_empty() {
        println!();
        println!("{}", "  Images with errors:".yellow().bold());
        let mut err_table = Table::new();
        err_table.set_header(vec![
            Cell::new("Image").add_attribute(Attribute::Bold),
            Cell::new("Error").add_attribute(Attribute::Bold).fg(Color::Red),
        ]);
        for (img, err) in image_errors {
            err_table.add_row(vec![Cell::new(img), Cell::new(err).fg(Color::Red)]);
        }
        println!("{}", err_table);
    }
    println!();
}
