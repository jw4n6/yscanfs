//! CSV output, SHA-256 hashing, file-type detection, and PE timestamp parsing.

use std::io;
use std::path::Path;

use chrono::{DateTime, TimeZone, Utc};
use sha2::{Digest, Sha256};

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/// One row in the output CSV / results summary.
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Source image filename (useful when scanning multiple images).
    pub source_image: String,
    /// UTC creation time of the matched file from NTFS `$STANDARD_INFORMATION`.
    pub timestamp: DateTime<Utc>,
    /// PE `TimeDateStamp` from the COFF header, if the file is a PE image.
    pub pe_compile_time: Option<DateTime<Utc>>,
    /// Human-readable rule title (from metadata or identifier).
    pub rule_title: String,
    /// Raw YARA rule identifier (used for source attribution and filtering).
    pub rule_identifier: String,
    /// The rule set this rule originated from.
    pub rule_source: String,
    /// Full path within the filesystem.
    pub file_path: String,
    /// SHA-256 of the matched file's bytes (lowercase hex).
    pub sha256: String,
    /// Detected file type, e.g. `.exe`.
    pub file_type: String,
    /// Comma-separated list of imported DLL names (PE files only; empty otherwise).
    pub pe_imports: String,
    /// PDB debug file path embedded in the PE debug directory (empty if absent).
    pub pdb_path: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Hashing
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the SHA-256 hash of `data` and return it as a lowercase hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

// ─────────────────────────────────────────────────────────────────────────────
// File-type detection
// ─────────────────────────────────────────────────────────────────────────────

/// Detect the file type from content bytes (via magic bytes), falling back to
/// the path extension.
///
/// PE files are distinguished: if the COFF Characteristics field has bit
/// `0x2000` (IMAGE_FILE_DLL) set the type is `.dll`, otherwise `.exe`.
///
/// For ADS entries (format `\path\to\file.exe:StreamName`):
/// - Magic byte detection is attempted first on the stream content
/// - If that fails, the stream name is used as the type (e.g. `Zone.Identifier`)
/// - The host file extension is NOT used as a fallback for ADS entries, as the
///   stream content is independent of the host file type
///
/// Returns a string like `.exe`, `.dll`, `.pdf`, `Zone.Identifier`, or `unknown`.
pub fn detect_type(data: &[u8], path: &str) -> String {
    if let Some(t) = infer::get(data) {
        let ext = t.extension();
        // infer returns "exe" for all PE files — distinguish DLL via COFF header.
        if ext == "exe" {
            return pe_subtype(data);
        }
        return format!(".{}", ext);
    }

    // For ADS entries, use the stream name as the type descriptor.
    if let Some(stream_name) = path.split(':').nth(1) {
        if !stream_name.is_empty() {
            return stream_name.to_string();
        }
    }

    // Unnamed stream — fall back to the file extension.
    let base = path.split(':').next().unwrap_or(path);
    match Path::new(base).extension().and_then(|e| e.to_str()) {
        Some(ext) if !ext.is_empty() => format!(".{}", ext.to_lowercase()),
        _ => "unknown".to_string(),
    }
}

/// Distinguish PE subtypes by reading the COFF Characteristics field.
///
/// IMAGE_FILE_DLL (0x2000) set → `.dll`
/// Otherwise → `.exe`
fn pe_subtype(data: &[u8]) -> String {
    // Need at least 64 bytes for DOS header + e_lfanew.
    if data.len() < 64 { return ".exe".to_string(); }
    if data[0] != b'M' || data[1] != b'Z' { return ".exe".to_string(); }

    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;

    // COFF Characteristics is at e_lfanew + 4 (sig) + 2 (Machine) + 2 (NumberOfSections)
    // + 4 (TimeDateStamp) + 4 (PointerToSymbolTable) + 4 (NumberOfSymbols)
    // + 2 (SizeOfOptionalHeader) = e_lfanew + 22, 2 bytes LE.
    let char_offset = match e_lfanew.checked_add(22) {
        Some(o) => o,
        None => return ".exe".to_string(),
    };
    if char_offset + 2 > data.len() { return ".exe".to_string(); }

    // Verify PE signature.
    if e_lfanew + 4 > data.len() { return ".exe".to_string(); }
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" { return ".exe".to_string(); }

    let characteristics = u16::from_le_bytes([data[char_offset], data[char_offset + 1]]);
    if characteristics & 0x2000 != 0 {
        ".dll".to_string()
    } else {
        ".exe".to_string()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PE timestamp parsing
// ─────────────────────────────────────────────────────────────────────────────

/// Parse the PE `TimeDateStamp` from a file's raw bytes.
///
/// Returns `None` if:
/// - The data is too short or lacks a valid DOS / PE signature.
/// - The timestamp is `0`, `0xFFFFFFFF`, or outside the plausible range
///   1995-01-01 to 2035-01-01 (values outside this window are almost certainly
///   absent, zeroed, or intentionally stomped to an implausible value).
///
/// # PE header layout
/// ```text
/// [0x00]        "MZ" DOS signature
/// [0x3C]        u32 LE  e_lfanew — byte offset of the PE signature
/// [e_lfanew+0]  "PE\0\0" signature
/// [e_lfanew+8]  u32 LE  TimeDateStamp (Unix seconds since 1970-01-01 UTC)
/// ```
pub fn parse_pe_timestamp(data: &[u8]) -> Option<DateTime<Utc>> {
    // Need at least 64 bytes for the DOS header.
    if data.len() < 64 {
        return None;
    }

    // DOS "MZ" magic at offset 0.
    if data[0] != b'M' || data[1] != b'Z' {
        return None;
    }

    // e_lfanew: 4-byte LE at 0x3C — points to "PE\0\0".
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;

    // Bounds check: need 12 bytes from e_lfanew (4 sig + 4 machine + 4 ts).
    let ts_offset = e_lfanew.checked_add(8)?;
    if ts_offset.checked_add(4)? > data.len() {
        return None;
    }

    // "PE\0\0" signature.
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }

    // TimeDateStamp: 4-byte LE at e_lfanew + 8.
    let ts = u32::from_le_bytes([
        data[ts_offset],
        data[ts_offset + 1],
        data[ts_offset + 2],
        data[ts_offset + 3],
    ]);

    // Reject obvious sentinel / placeholder values.
    if ts == 0 || ts == 0xFFFF_FFFF {
        return None;
    }

    // Plausibility window: 1995-01-01 … 2035-01-01 UTC.
    // Timestamps outside this range are almost always zeroed, absent, or
    // stomped to an implausible value (e.g. the classic 2112-09-17 stomp).
    // Note: a *suspicious* timestamp inside this window (e.g. 1999-11-11) is
    // still returned — the caller can decide whether to flag it.
    const MIN_TS: u32 = 788_918_400;   // 1995-01-01T00:00:00Z
    const MAX_TS: u32 = 2_051_222_400; // 2035-01-01T00:00:00Z
    if ts < MIN_TS || ts > MAX_TS {
        return None;
    }

    Utc.timestamp_opt(ts as i64, 0).single()
}

// ─────────────────────────────────────────────────────────────────────────────
// CSV writer
// ─────────────────────────────────────────────────────────────────────────────

/// Write `results` to `writer` as CSV.
///
/// Columns (in order):
/// `Source Image`, `Timestamp`, `PE Compile Time`, `Rule Title`,
/// `File Path`, `SHA256`, `Type`
pub fn write_csv<W: io::Write>(writer: W, results: &[ScanResult]) -> anyhow::Result<()> {
    let mut wtr = csv::Writer::from_writer(writer);

    wtr.write_record([
        "Source Image",
        "Timestamp",
        "PE Compile Time",
        "Rule Title",
        "Rule Source",
        "File Path",
        "SHA256",
        "Type",
        "PE Imports",
        "PDB Path",
    ])?;

    for r in results {
        let pe_ts = r.pe_compile_time
            .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
            .unwrap_or_default();

        wtr.write_record([
            r.source_image.as_str(),
            r.timestamp.format("%Y-%m-%dT%H:%M:%SZ").to_string().as_str(),
            pe_ts.as_str(),
            r.rule_title.as_str(),
            r.rule_source.as_str(),
            r.file_path.as_str(),
            r.sha256.as_str(),
            r.file_type.as_str(),
            r.pe_imports.as_str(),
            r.pdb_path.as_str(),
        ])?;
    }

    wtr.flush()?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pe(ts: u32) -> Vec<u8> {
        let mut data = vec![0u8; 512];
        // DOS "MZ" signature
        data[0] = b'M';
        data[1] = b'Z';
        // e_lfanew = 0x40 (64)
        data[0x3C] = 0x40;
        // PE signature at offset 0x40
        data[0x40] = b'P';
        data[0x41] = b'E';
        data[0x42] = 0;
        data[0x43] = 0;
        // Machine (x86-64) at 0x44 — just for completeness
        data[0x44] = 0x64;
        data[0x45] = 0x86;
        // TimeDateStamp at 0x48 (e_lfanew + 8)
        let ts_bytes = ts.to_le_bytes();
        data[0x48] = ts_bytes[0];
        data[0x49] = ts_bytes[1];
        data[0x4A] = ts_bytes[2];
        data[0x4B] = ts_bytes[3];
        data
    }

    #[test]
    fn parses_valid_pe_timestamp() {
        // 2018-08-31T22:01:00Z → Unix ts 1535753340 (within our window)
        let ts: u32 = 1_535_753_340;
        let data = make_pe(ts);
        let result = parse_pe_timestamp(&data);
        assert!(result.is_some());
        let dt = result.unwrap();
        assert_eq!(dt.format("%Y-%m-%d").to_string(), "2018-08-31");
    }

    #[test]
    fn rejects_zero_timestamp() {
        assert!(parse_pe_timestamp(&make_pe(0)).is_none());
    }

    #[test]
    fn rejects_all_ones_timestamp() {
        assert!(parse_pe_timestamp(&make_pe(0xFFFF_FFFF)).is_none());
    }

    #[test]
    fn rejects_pre_1995_timestamp() {
        // 1994-12-31 → below MIN_TS
        assert!(parse_pe_timestamp(&make_pe(788_832_000)).is_none());
    }

    #[test]
    fn rejects_post_2035_timestamp() {
        assert!(parse_pe_timestamp(&make_pe(2_051_222_401)).is_none());
    }

    #[test]
    fn rejects_non_mz_header() {
        let mut data = make_pe(1_535_753_340);
        data[0] = b'X';
        assert!(parse_pe_timestamp(&data).is_none());
    }

    #[test]
    fn rejects_bad_pe_signature() {
        let mut data = make_pe(1_535_753_340);
        data[0x40] = b'X'; // corrupt PE signature
        assert!(parse_pe_timestamp(&data).is_none());
    }

    #[test]
    fn rejects_too_short_data() {
        assert!(parse_pe_timestamp(&[b'M', b'Z', 0, 0]).is_none());
    }

    #[test]
    fn rejects_e_lfanew_out_of_bounds() {
        let mut data = make_pe(1_535_753_340);
        // Point e_lfanew far past end of data
        let far: u32 = 0x0FFF_FFFF;
        let b = far.to_le_bytes();
        data[0x3C] = b[0];
        data[0x3D] = b[1];
        data[0x3E] = b[2];
        data[0x3F] = b[3];
        assert!(parse_pe_timestamp(&data).is_none());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON output
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level JSON report written when `--output-format json` is specified.
#[derive(serde::Serialize)]
pub struct JsonReport<'a> {
    pub scan_time:           String,
    pub total_files_scanned: u64,
    pub total_hits:          usize,
    pub results:             Vec<JsonResult<'a>>,
}

/// One hit serialised into the JSON report.
#[derive(serde::Serialize)]
pub struct JsonResult<'a> {
    pub source_image:    &'a str,
    pub timestamp:       String,
    pub pe_compile_time: Option<String>,
    pub rule_title:      &'a str,
    pub rule_source:     &'a str,
    pub file_path:       &'a str,
    pub sha256:          &'a str,
    pub file_type:       &'a str,
    pub pe_imports:      &'a str,
    pub pdb_path:        &'a str,
}

/// Write `results` to `writer` as a pretty-printed JSON report.
pub fn write_json<W: io::Write>(
    writer: W,
    results: &[ScanResult],
    total_files_scanned: u64,
) -> anyhow::Result<()> {
    let report = JsonReport {
        scan_time: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        total_files_scanned,
        total_hits: results.len(),
        results: results.iter().map(|r| JsonResult {
            source_image: &r.source_image,
            timestamp:    r.timestamp.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            pe_compile_time: r.pe_compile_time
                .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
            rule_title:  &r.rule_title,
            rule_source: &r.rule_source,
            file_path:   &r.file_path,
            sha256:      &r.sha256,
            file_type:   &r.file_type,
            pe_imports:  &r.pe_imports,
            pdb_path:    &r.pdb_path,
        }).collect(),
    };

    serde_json::to_writer_pretty(writer, &report)?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// PE metadata enrichment
// ─────────────────────────────────────────────────────────────────────────────

/// Extract the list of imported DLL names from a PE file's import directory.
///
/// Returns an empty `Vec` if the file is not a PE, has no imports, or if
/// parsing fails at any point. Each string is the DLL name as stored in the
/// import descriptor (e.g. `"kernel32.dll"`).
pub fn pe_imported_dlls(data: &[u8]) -> Vec<String> {
    pe_imports_inner(data).unwrap_or_default()
}

/// Extract the PDB debug file path from the PE debug directory.
///
/// Returns `None` if the file is not a PE, has no debug directory,
/// or if the debug entry is not of type `IMAGE_DEBUG_TYPE_CODEVIEW` (2).
pub fn pe_pdb_path(data: &[u8]) -> Option<String> {
    pe_pdb_inner(data)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn pe_rva_to_offset(_data: &[u8], rva: u32, sections: &[(u32, u32, u32)]) -> Option<usize> {
    // sections: Vec<(virtual_address, size_of_raw_data, pointer_to_raw_data)>
    for &(va, sz, raw) in sections {
        if rva >= va && rva < va.saturating_add(sz) {
            let offset = rva - va + raw;
            return Some(offset as usize);
        }
    }
    None
}

fn read_u16_le(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off+2).map(|b| u16::from_le_bytes(b.try_into().unwrap()))
}
fn read_u32_le(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off+4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

/// Parse section table: returns Vec<(virtual_address, size_of_raw_data, pointer_to_raw_data)>
fn parse_sections(data: &[u8], pe_off: usize) -> Option<Vec<(u32, u32, u32)>> {
    // Machine at pe+4, NumberOfSections at pe+6, SizeOfOptionalHeader at pe+20
    let num_sections = read_u16_le(data, pe_off + 6)? as usize;
    let opt_size     = read_u16_le(data, pe_off + 20)? as usize;
    let section_base = pe_off + 24 + opt_size;

    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let off = section_base + i * 40;
        if off + 40 > data.len() { break; }
        let va  = read_u32_le(data, off + 12)?;
        let sz  = read_u32_le(data, off + 16)?;
        let raw = read_u32_le(data, off + 20)?;
        sections.push((va, sz.max(1), raw));
    }
    Some(sections)
}

fn pe_imports_inner(data: &[u8]) -> Option<Vec<String>> {
    if data.len() < 64 { return None; }
    if data[0] != b'M' || data[1] != b'Z' { return None; }

    let e_lfanew = read_u32_le(data, 0x3C)? as usize;
    if e_lfanew + 4 > data.len() { return None; }
    if &data[e_lfanew..e_lfanew+4] != b"PE\0\0" { return None; }

    let magic = read_u16_le(data, e_lfanew + 24)?;
    // Import directory: PE32 at optional+104, PE32+ at optional+120.
    let import_dir_rva_off = match magic {
        0x10B => e_lfanew + 24 + 104, // PE32
        0x20B => e_lfanew + 24 + 120, // PE32+
        _     => return None,
    };

    let import_dir_rva  = read_u32_le(data, import_dir_rva_off)?;
    let import_dir_size = read_u32_le(data, import_dir_rva_off + 4)?;
    if import_dir_rva == 0 || import_dir_size == 0 { return Some(vec![]); }

    let sections = parse_sections(data, e_lfanew)?;
    let import_off = pe_rva_to_offset(data, import_dir_rva, &sections)?;

    let mut dlls = Vec::new();
    let mut i = import_off;
    // Each import descriptor is 20 bytes; ends with an all-zero entry.
    loop {
        if i + 20 > data.len() { break; }
        let name_rva = read_u32_le(data, i + 12)?;
        // OriginalFirstThunk + FirstThunk + ForwarderChain + Name + FirstThunk
        // An all-zero descriptor marks the end.
        if data[i..i+20].iter().all(|&b| b == 0) { break; }
        if name_rva != 0 {
            if let Some(name_off) = pe_rva_to_offset(data, name_rva, &sections) {
                let name = data.get(name_off..)
                    .and_then(|s| s.iter().position(|&b| b == 0)
                        .map(|end| String::from_utf8_lossy(&s[..end]).into_owned()));
                if let Some(n) = name {
                    if !n.is_empty() { dlls.push(n.to_ascii_lowercase()); }
                }
            }
        }
        i += 20;
        if dlls.len() > 256 { break; } // sanity cap
    }
    Some(dlls)
}

fn pe_pdb_inner(data: &[u8]) -> Option<String> {
    if data.len() < 64 { return None; }
    if data[0] != b'M' || data[1] != b'Z' { return None; }

    let e_lfanew = read_u32_le(data, 0x3C)? as usize;
    if e_lfanew + 4 > data.len() { return None; }
    if &data[e_lfanew..e_lfanew+4] != b"PE\0\0" { return None; }

    let magic = read_u16_le(data, e_lfanew + 24)?;
    // Debug directory: PE32 at optional+128, PE32+ at optional+144.
    let debug_dir_rva_off = match magic {
        0x10B => e_lfanew + 24 + 128,
        0x20B => e_lfanew + 24 + 144,
        _     => return None,
    };

    let debug_dir_rva  = read_u32_le(data, debug_dir_rva_off)?;
    let debug_dir_size = read_u32_le(data, debug_dir_rva_off + 4)?;
    if debug_dir_rva == 0 || debug_dir_size == 0 { return None; }

    let sections = parse_sections(data, e_lfanew)?;
    let debug_off = pe_rva_to_offset(data, debug_dir_rva, &sections)?;

    // Each debug directory entry is 28 bytes.
    // IMAGE_DEBUG_DIRECTORY layout:
    //   +0  Characteristics    (4)
    //   +4  TimeDateStamp      (4)
    //   +8  MajorVersion       (2)
    //   +10 MinorVersion       (2)
    //   +12 Type               (4)  ← IMAGE_DEBUG_TYPE_CODEVIEW = 2
    //   +16 SizeOfData         (4)
    //   +20 AddressOfRawData   (4)  ← RVA (not used here)
    //   +24 PointerToRawData   (4)  ← absolute file offset ← use this
    let num_entries = (debug_dir_size / 28) as usize;
    for i in 0..num_entries {
        let off = debug_off + i * 28;
        if off + 28 > data.len() { break; }
        let debug_type = read_u32_le(data, off + 12)?;
        if debug_type != 2 { continue; } // IMAGE_DEBUG_TYPE_CODEVIEW

        let raw_data_size = read_u32_le(data, off + 16)? as usize;
        let raw_data_ptr  = read_u32_le(data, off + 24)? as usize; // PointerToRawData

        if raw_data_size < 24 { continue; }
        if raw_data_ptr == 0 || raw_data_ptr + raw_data_size > data.len() { continue; }
        let cv = &data[raw_data_ptr..raw_data_ptr + raw_data_size];

        // CodeView record: "RSDS" + 16-byte GUID + 4-byte age + NUL-terminated PDB path.
        if &cv[..4] != b"RSDS" { continue; }
        let path_bytes = &cv[24..];
        let path_end = path_bytes.iter().position(|&b| b == 0)
            .unwrap_or(path_bytes.len());
        let path = String::from_utf8_lossy(&path_bytes[..path_end]).into_owned();
        if !path.is_empty() { return Some(path); }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Result deduplication
// ─────────────────────────────────────────────────────────────────────────────

/// Deduplicate scan results by `(rule_identifier, sha256)`.
///
/// For each unique `(rule, hash)` pair all matching file paths are merged
/// into the `file_path` field of a single representative `ScanResult`,
/// separated by `"; "`. Every rule that matched a given binary still produces
/// its own row — this function only collapses duplicate paths for the *same*
/// rule matching the *same* binary.
///
/// The representative row chosen for each group is the one with the
/// lexicographically earliest `file_path`. Rows are sorted in the output by
/// hit count descending (most-seen binaries first) then by rule title.
pub fn deduplicate_results(results: Vec<ScanResult>) -> Vec<ScanResult> {
    use std::collections::HashMap;

    if results.is_empty() {
        return results;
    }

    // Group by (rule_identifier, sha256).
    // Use an IndexMap-style approach via a Vec + HashMap to preserve
    // insertion order within each group (earliest path first).
    let mut groups: HashMap<(String, String), Vec<usize>> = HashMap::new();
    let mut order: Vec<(String, String)> = Vec::new(); // insertion order

    for (idx, r) in results.iter().enumerate() {
        let key = (r.rule_identifier.clone(), r.sha256.clone());
        let entry = groups.entry(key.clone()).or_insert_with(|| {
            order.push(key);
            Vec::new()
        });
        entry.push(idx);
    }

    // Build (path_count, ScanResult) tuples for sorting.
    let mut deduped: Vec<(usize, ScanResult)> = order
        .into_iter()
        .filter_map(|key| {
            let indices = groups.remove(&key)?;
            if indices.is_empty() { return None; }

            // Collect and sort paths so the merged output is deterministic.
            let mut paths: Vec<&str> = indices.iter()
                .map(|&i| results[i].file_path.as_str())
                .collect();
            paths.sort_unstable();
            paths.dedup();

            // Use the first result as the representative row.
            let mut rep = results[indices[0]].clone();
            rep.file_path = paths.join("; ");
            Some((paths.len(), rep))
        })
        .collect();

    // Sort: most locations first (highest forensic interest), then by rule title.
    deduped.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.rule_title.cmp(&b.1.rule_title)));

    deduped.into_iter().map(|(_, r)| r).collect()
}
