# YScanFS

YScanFS reads forensic disk images in read-only mode, traverses their filesystems, and applies YARA rules to every file — including Volume Shadow Copy (VSS) snapshots.

```
__   __ ____    ____     _     _   _  _____  ____
\ \ / // ___|  / ___|   / \   | \ | ||  ___|/ ___|
 \ V / \___ \ | |      / _ \  |  \| || |_   \___ \
  | |   ___) || |___  / ___ \ | |\  ||  _|   ___) |
  |_|  |____/  \____|/_/   \_\|_| \_||_|    |____/

YARA scanner for forensic disk images | https://github.com/jw4n6/yscanfs

Loading YARA rules…
  ✓ Loaded 11655 rule(s) in 0.8s  [cache hit]

Discovering disk images…
  ✓ Found 'evidence.E01' (EWF)

Scanning: evidence.E01
  ⠴ 83186 files  •  1247/s  •  1m 7s

  ✓ Results  → 'yscanfs_20260424_143022.csv'
  ✓ Scan log → 'logs/yscanfs_20260424_143022.log'

─────────────────────────────────────────
  • Files scanned : 83186  (1247/s)
  • Rules matched  : 2
  • Total hits     : 3
  • Time elapsed   : 1m 7s
─────────────────────────────────────────

┌──────────────────────────────────────────┬──────┬───────┐
│ Rule                                     │ Hits │ Files │
╞══════════════════════════════════════════╪══════╪═══════╡
│ Windows_Trojan_CobaltStrike_7f8da98a     │    2 │     2 │
│ SUSP_PowerShell_Encoded_Exec             │    1 │     1 │
└──────────────────────────────────────────┴──────┴───────┘
```



## Disclaimer

YScanFS was developed by Claude, an AI assistant by Anthropic. The development process was iterative — spanning architecture decisions, feature implementation, bug fixes, and code review across many sessions.
I provided forensic domain expertise, real-world testing on actual disk images, product direction, and all final decisions on what the tool does and how it behaves. Claude assisted with Rust implementation and code review throughout the process.


## Supported Disk Image Formats

| Format | Extensions | Notes |
|--------|------------|-------|
| EWF | `.E01`–`.E99`, `.EAA`–`.EZZ` | Single and segmented Expert Witness Format |
| Raw / DD | `.raw`, `.dd`, `.img`, `.bin` | Flat uncompressed images |
| Split raw | `.001`, `.002`… | Numbered segment images |

## Supported Filesystems

| Filesystem | Notes |
|------------|-------|
| NTFS | Full support including Alternate Data Streams (ADS) |
| EXT4 | Full support including EXT2/EXT3; timestamps shown as epoch (ext4-view limitation) |



## Features

- **Multi-format image support** — EWF, raw/DD, split raw

- **Multi-filesystem support** — NTFS (including ADS) and EXT4/EXT2/EXT3

- **VSS snapshot scanning** — enumerate and scan all Volume Shadow Copy snapshots on NTFS volumes

- **YARA-X engine** — fast, modern YARA implementation with cross-platform compatibility

- **YARA Forge integration** — one-command sync of curated community rules (~11k+ rules)

- **Elastic Security rules** — optional sync of Elastic Security YARA rules (~1k rules, Elastic License 2.0)

- **Rule compilation cache** — compiled rules cached to disk; repeat runs load in under 1 second

- **Parallel scanning** — YARA matching runs across all available CPU cores (up to 8 workers)

- **Recursive directory scanning** — `-d` walks subdirectories for all supported image formats

- **Hash allowlist** — skip known-good files by SHA-256 (e.g. NSRL hash set)

- **Rule filtering** — `--include-rule` and `--exclude-rule` with glob pattern support

- **Deduplication mode** — `--unique-files` consolidates duplicate paths per rule into a single row

- **CSV and JSON output** — structured results ready for SIEM, Excel, or scripting pipelines

- **PE metadata enrichment** — PE compile timestamp, imported DLLs, and PDB path in output

- **Rule source tracking** — CSV/JSON identifies whether each match came from YARA Forge, Elastic Security, or custom rules

- **Cross-ruleset deduplication** — duplicate rule names across rule sets deduplicated at load time

- **SHA-256 hashing** — fingerprints every matched file

- **File type detection** — magic byte identification with extension fallback; correctly distinguishes `.dll` from `.exe`

- **Quiet mode** — suppress all output except the result path, for scripting and automation

- **Automatic logging** — scan logs written to `logs/` on every run

- **Debug mode** — verbose logging for troubleshooting rule compatibility issues


## Downloads

Please download the latest version of YScanFS from the [Releases](https://github.com/jw4n6/yscanfs/releases) page.

Binaries are available for the following architectures:

- Windows Intel 64-bit (`yscanfs-x.x.x.exe`)
- Linux Intel 64-bit (`yscanfs-x.x.x`)



### Build from source

```bash
git clone https://github.com/jw4n6/yscanfs
cd yscanfs
cargo build --release
```

Binary: `target/release/yscanfs` (Linux/macOS) or `target\release\yscanfs.exe` (Windows)

To compile for Windows, please refer to the [official rust website](https://rust-lang.github.io/rustup/installation/windows-msvc.html) for further instructions.



## Quick Start

```bash
# 1. Download YARA Forge core, Elastic Security rules and scan a disk image
./yscanfs -s core --accept-elastic-license -f /mnt/labs/disk-images/DC01.E01 --vss --unique-files -o /mnt/labs/DC01.csv
```



## Usage

```
yscanfs [OPTIONS]
```



### Options

| Flag | Description |
|------|-------------|
| `-f FILE` | Path to a single disk image |
| `-d DIR` | Directory of disk images to scan (recursive) |
| `-s [RULESET]` | Sync YARA rules (see Rule Sets below) |
| `--accept-elastic-license` | Accept Elastic License 2.0 and download Elastic Security rules |
| `-r DIR` | Custom rules directory (default: `./rules/`) |
| `-m MB` | Maximum file size to scan in MB (default: 50) |
| `--allowlist FILE` | Skip files whose SHA-256 appears in this file (one hash per line, `#` for comments) |
| `-o FILE` | Output file path (default: `yscanfs_<timestamp>.csv`) |
| `-F FORMAT` | Output format: `csv` (default) or `json` |
| `--unique-files` | Deduplicate results by (rule, SHA-256) — consolidate duplicate paths per rule |
| `--vss` | Scan VSS snapshots in addition to the live volume |
| `--list-vss` | List VSS snapshots found in the image and exit |
| `--include-rule PATTERN` | Only run rules matching this glob pattern (repeatable) |
| `--exclude-rule PATTERN` | Skip rules matching this glob pattern (repeatable) |
| `-q` | Quiet mode — print only the output file path on success |
| `-D` | Enable verbose debug logging |
| `-V` | Print version |
| `-h` / `--help` | Print help |



### Rule Sets

| Value | Source | Rules | Notes |
|-------|--------|-------|-------|
| `core` | YARA Forge | ~5k | High accuracy, low false positives |
| `extended` | YARA Forge | ~10k | Broader coverage |
| `full` | YARA Forge | ~11k | All operational rules (default) |
| `elastic` | Elastic Security | ~1k | Requires `--accept-elastic-license` |

```bash
yscanfs -s                                    # YARA Forge full (default)
yscanfs -s core                               # YARA Forge core only
yscanfs -s elastic --accept-elastic-license   # Elastic Security only
yscanfs -s --accept-elastic-license           # YARA Forge full + Elastic
```



## Examples

```bash
# Scan a single EWF image
yscanfs -f evidence.E01

# Scan all images in a case directory (recursive)
yscanfs -d /cases/2026-001/

# Scan live volume AND all VSS snapshots
yscanfs -f evidence.E01 --vss

# List VSS snapshots without scanning
yscanfs -f evidence.E01 --list-vss

# Skip known-good system files using NSRL hash set
yscanfs -f evidence.E01 --allowlist nsrl.txt

# Only run Cobalt Strike and Mimikatz rules
yscanfs -f evidence.E01 --include-rule "*CobaltStrike*" --include-rule "*Mimikatz*"

# Skip PUP and adware rules
yscanfs -f evidence.E01 --exclude-rule "PUP_*" --exclude-rule "*Adware*"

# Deduplicate: one row per (rule, file hash) instead of one row per path
yscanfs -f evidence.E01 --unique-files

# JSON output for SIEM or scripting
yscanfs -f evidence.E01 -F json -o results.json

# Full scan: VSS + deduplication + JSON output
yscanfs -f evidence.E01 --vss --unique-files -F json
```

## Output

### CSV columns

| Column | Description |
|--------|-------------|
| `Source Image` | Image filename |
| `Timestamp` | File creation/modification time (UTC) |
| `PE Compile Time` | PE `TimeDateStamp` from COFF header (if applicable) |
| `Rule Title` | Matched YARA rule name |
| `Rule Source` | `YARA Forge`, `Elastic Security`, or `Custom` |
| `File Path` | Full path within the filesystem. NTFS ADS entries shown as `\path\file:StreamName`. VSS entries prefixed with `[VSS#N YYYY-MM-DD]` |
| `SHA256` | SHA-256 hash of the matched file |
| `Type` | Detected file type (e.g. `.exe`, `.dll`, `.pdf`) |
| `PE Imports` | Comma-separated imported DLL names (PE files only) |
| `PDB Path` | PDB debug symbol path from PE debug directory (if present) |

When `--unique-files` is used, the `File Path` column contains all matching paths separated by `"; "`.



### JSON output

```json
{
  "scan_time": "2026-04-24T14:30:22Z",
  "total_files_scanned": 83186,
  "total_hits": 3,
  "results": [
    {
      "source_image": "evidence.E01",
      "timestamp": "2024-03-15T09:41:22Z",
      "pe_compile_time": "2023-11-02T14:22:11Z",
      "rule_title": "Windows_Trojan_CobaltStrike_7f8da98a",
      "rule_source": "YARA Forge",
      "file_path": "\\Windows\\Temp\\svch0st.exe",
      "sha256": "a3f8c2d1e9b4f607...",
      "file_type": ".exe",
      "pe_imports": "kernel32.dll,ntdll.dll,wininet.dll",
      "pdb_path": "C:\\Users\\operator\\cs\\implant.pdb"
    }
  ]
}
```



### Log files

```
logs/
  yscanfs_20260424_143022.log         # warnings and errors
  yscanfs_20260424_143022_debug.log   # verbose output (only with -D)
```



## Rule Compilation Cache

On the first run after syncing or updating rules, YScanFS compiles all `.yar` files and saves the result to `rules/.cache/`. Subsequent runs load the compiled binary directly — reducing rule loading time from ~20 seconds to under 1 second.

The cache is automatically invalidated and rebuilt whenever rules change (detected by comparing file paths, sizes, and modification timestamps).



## VSS Snapshot Scanning

```bash
# See what snapshots are available
yscanfs -f evidence.E01 --list-vss

  [+] Partition 1  Snapshot #01  2024-11-15 03:00:21 UTC  (119 GB)
  [+] Partition 1  Snapshot #02  2024-11-22 03:00:18 UTC  (119 GB)
  [+] Partition 1  Snapshot #03  2024-11-29 03:00:31 UTC  (119 GB)
  3 total snapshot(s)

# Scan all of them
yscanfs -f evidence.E01 --vss
```

VSS hits appear in results with the `File Path` prefixed by `[VSS#N YYYY-MM-DD]`, making it immediately clear which snapshot a hit came from:

```
[VSS#1 2024-11-15] \Windows\Temp\svch0st.exe
```

VSS scanning only applies to NTFS partitions. The live volume is always scanned first.



## YARA Rule Compatibility

YScanFS uses the [YARA-X](https://github.com/VirusTotal/yara-x) engine (99% compatible with YARA 4.x). When a rule file fails to compile, YScanFS automatically removes only the failing rule and retries — preserving the rest of the rule set. Removed rules are reported in the scan log.



## YARA Forge

Rules are sourced from [YARA Forge](https://yarahq.github.io/) — a weekly-updated aggregation of community repositories including ReversingLabs, ESET, Malpedia, Signature Base, Volexity, GCTI, CAPE, BinaryAlert, FireEye-RT, McAfee ATR, JPCERTCC, Telekom Security, SecuInfra, and others.



## Elastic Security Rules

Elastic Security YARA rules are sourced from the [protections-artifacts](https://github.com/elastic/protections-artifacts) repository and are licensed under the **Elastic License 2.0**. Passing `--accept-elastic-license` confirms that you accept the license terms at [https://www.elastic.co/licensing/elastic-license](https://www.elastic.co/licensing/elastic-license).



## Limitations

- **EXT4 timestamps** — `ext4-view` v0.9.3 does not expose inode timestamps; the `Timestamp` column shows `1970-01-01T00:00:00Z` for EXT4 files
- **EWF v2 (Ex01)** — not yet supported by the underlying `ewf` crate


## License

MIT — see [LICENSE](LICENSE)


### Dependency Licenses

| Crate | License | Notes |
|-------|---------|-------|
| vshadow | AGPL-3.0 | VSS parsing. Source published on GitHub satisfies AGPL requirements |
| colored | MPL-2.0 | Terminal colours. File-level copyleft; does not affect yscanfs |
| yara-x | BSD-3-Clause | YARA engine |
| All other crates | MIT or Apache-2.0 | Permissive |



## Acknowledgements

- [YARA-X](https://github.com/VirusTotal/yara-x)
- [YARA Forge](https://yarahq.github.io/)
- [Elastic Security](https://github.com/elastic/protections-artifacts)
- [ntfs](https://github.com/ColinFinck/ntfs)
- [ewf](https://crates.io/crates/ewf)
- [ext4-view](https://github.com/nicholasbishop/ext4-view-rs)
- [vshadow](https://crates.io/crates/vshadow)
