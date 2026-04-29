//! Disk-image access: format detection, EWF/raw readers,
//! MBR/GPT partition parsing, and `PartitionReader`.

use anyhow::{anyhow, Context, Result};
use log::info;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

pub const SECTOR_SIZE: u64 = 512;

const MBR_BOOT_SIG: [u8; 2] = [0x55, 0xAA];
const PARTITION_TABLE_OFFSET: usize = 446;
const PARTITION_ENTRY_SIZE: usize = 16;
const PARTITION_COUNT: usize = 4;

const PT_GPT_PROTECTIVE: u8 = 0xEE;
const PT_EXTENDED_CHS: u8 = 0x05;
const PT_EXTENDED_LBA: u8 = 0x0F;
const PT_EXTENDED_LINUX: u8 = 0x85;

const NTFS_OEM_ID: &[u8; 8] = b"NTFS    ";
const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";

const GPT_BASIC_DATA_GUID: [u8; 16] = [
    0xA2, 0xA0, 0xD0, 0xEB,
    0xE5, 0xB9,
    0x33, 0x44,
    0x87, 0xC0,
    0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7,
];

/// Magic bytes used to identify image formats.
const EWF_MAGIC: &[u8; 8] = b"EVF\x09\x0D\x0A\xFF\x00";

/// EXT2/3/4 superblock magic at offset 1080 (superblock offset 1024 + 56).
const EXT4_MAGIC: [u8; 2] = [0x53, 0xEF];
const EXT4_MAGIC_OFFSET: u64 = 1080;

// ─────────────────────────────────────────────────────────────────────────────
// Filesystem type detection
// ─────────────────────────────────────────────────────────────────────────────

/// Filesystem types that yscanfs can walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemType {
    Ntfs,
    Ext4,
}

/// Detect the filesystem type at `partition_offset` within `img`.
///
/// Checks NTFS OEM-ID first (bytes 3–10 of the VBR), then EXT4 superblock
/// magic at offset 1080 relative to the partition start.
pub fn detect_filesystem(
    img: &mut dyn ReadSeek,
    partition_offset: u64,
) -> Option<FilesystemType> {
    // NTFS: OEM-ID "NTFS    " at bytes 3–10 of the VBR.
    let mut vbr = [0u8; 16];
    if img.seek(SeekFrom::Start(partition_offset)).is_ok()
        && img.read_exact(&mut vbr).is_ok()
        && &vbr[3..11] == NTFS_OEM_ID
    {
        return Some(FilesystemType::Ntfs);
    }

    // EXT4: magic 0xEF53 at superblock offset + 56 (= partition offset + 1080).
    let mut magic = [0u8; 2];
    let ext4_off = partition_offset + EXT4_MAGIC_OFFSET;
    if img.seek(SeekFrom::Start(ext4_off)).is_ok()
        && img.read_exact(&mut magic).is_ok()
        && magic == EXT4_MAGIC
    {
        return Some(FilesystemType::Ext4);
    }

    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/// Metadata about a single partition found in a disk image.
#[derive(Debug, Clone)]
pub struct PartitionInfo {
    pub offset: u64,
    pub size: u64,
    pub filesystem: FilesystemType,
}

/// Convenience alias used throughout the codebase.
pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}

// ─────────────────────────────────────────────────────────────────────────────
// Supported formats
// ─────────────────────────────────────────────────────────────────────────────

/// Disk image formats supported by yscanfs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    /// Expert Witness Format (.E01, .E02, … / .EAA, .EAB, …)
    Ewf,
    /// Raw / DD flat image (.raw, .dd, .img, .bin)
    Raw,
    /// Split raw image (.001, .002, …)
    SplitRaw,
}

impl ImageFormat {
    /// Detect the format of an image from its extension and magic bytes.
    pub fn detect(path: &Path) -> Result<Self> {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        // Extension-based fast path for common EWF numeric suffixes.
        match ext.as_str() {
            "raw" | "dd" | "img" | "bin" => return Ok(Self::Raw),
            _ => {}
        }

        // EWF numeric extensions: .e01–.e99 (.eXX where XX are two digits)
        if ext.len() == 3 {
            let b = ext.as_bytes();
            if b[0] == b'e' && b[1].is_ascii_digit() && b[2].is_ascii_digit() && &ext != "e00" {
                return Ok(Self::Ewf);
            }
        }

        // EWF alpha continuation extensions: .eaa–.ezz
        if ext.len() == 3 {
            let b = ext.as_bytes();
            if b[0] == b'e' && b[1].is_ascii_lowercase() && b[2].is_ascii_lowercase()
                && !b[1].is_ascii_digit() && !b[2].is_ascii_digit()
            {
                return Ok(Self::Ewf);
            }
        }

        // Numeric split-raw extensions (.001, .002, …)
        if ext.len() == 3 && ext.bytes().all(|b| b.is_ascii_digit()) {
            return Ok(Self::SplitRaw);
        }

        // Fall back to magic byte detection.
        let mut f = File::open(path)
            .with_context(|| format!("cannot open '{}' for format detection", path.display()))?;
        let mut magic = [0u8; 8];
        f.read_exact(&mut magic).unwrap_or(());

        if &magic[..8] == EWF_MAGIC {
            return Ok(Self::Ewf);
        }

        // Unknown — treat as raw; partition detection will give a clear error.
        Ok(Self::Raw)
    }

    /// All file extensions recognised as disk images.
    pub fn all_extensions() -> &'static [&'static str] {
        &[
            // EWF
            "e01",
            // Raw
            "raw", "dd", "img", "bin",
        ]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Image opening
// ─────────────────────────────────────────────────────────────────────────────

/// Open a disk image in read-only mode and return a boxed `Read + Seek`.
///
/// Supports EWF (.E01), raw/DD (.raw, .dd, .img, .bin), and split raw (.001…).
pub fn open_image(path: &Path) -> Result<Box<dyn ReadSeek>> {
    let fmt = ImageFormat::detect(path)?;
    match fmt {
        ImageFormat::Ewf => {
            let reader = ewf::EwfReader::open(path)
                .map_err(|e| anyhow!("cannot open EWF image '{}': {}", path.display(), e))?;
            Ok(Box::new(reader))
        }
        ImageFormat::Raw => {
            let f = File::open(path)
                .with_context(|| format!("cannot open image '{}'", path.display()))?;
            Ok(Box::new(f))
        }
        ImageFormat::SplitRaw => {
            let reader = SplitRawReader::open(path)
                .with_context(|| format!("cannot open split raw image '{}'", path.display()))?;
            Ok(Box::new(reader))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Split raw reader (.001, .002, …)
// ─────────────────────────────────────────────────────────────────────────────

/// A `Read + Seek` reader that presents a sequence of numbered raw segment
/// files (`.001`, `.002`, …) as a single continuous byte stream.
pub struct SplitRawReader {
    segments: Vec<(u64, File)>, // (start_offset_in_image, file)
    total_size: u64,
    pos: u64,
}

impl SplitRawReader {
    /// Open a split raw image starting from `first` (e.g. `image.001`).
    /// Discovers all consecutive segments in the same directory.
    pub fn open(first: &Path) -> Result<Self> {
        let stem = first
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow!("cannot determine stem of '{}'", first.display()))?;

        let parent = first.parent().unwrap_or_else(|| Path::new("."));

        // Collect all segments with numeric extensions, sorted.
        let mut paths: Vec<std::path::PathBuf> = std::fs::read_dir(parent)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_stem().and_then(|s| s.to_str()) == Some(stem)
                    && p.extension()
                        .and_then(|e| e.to_str())
                        .map(|e| e.len() == 3 && e.bytes().all(|b| b.is_ascii_digit()))
                        .unwrap_or(false)
            })
            .collect();

        paths.sort();

        if paths.is_empty() {
            return Err(anyhow!("no segment files found for '{}'", first.display()));
        }

        let mut segments = Vec::with_capacity(paths.len());
        let mut offset = 0u64;

        for p in &paths {
            let f = File::open(p)
                .with_context(|| format!("cannot open segment '{}'", p.display()))?;
            let size = f.metadata()?.len();
            segments.push((offset, f));
            offset += size;
        }

        Ok(Self {
            segments,
            total_size: offset,
            pos: 0,
        })
    }
}

impl Read for SplitRawReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.total_size {
            return Ok(0);
        }

        // Find the segment that contains self.pos.
        let seg_idx = self
            .segments
            .partition_point(|(start, _)| *start <= self.pos)
            .saturating_sub(1);

        let (seg_start, ref mut file) = self.segments[seg_idx];
        let seg_offset = self.pos - seg_start;

        file.seek(SeekFrom::Start(seg_offset))?;

        // Read at most to the end of this segment.
        let seg_size = file.metadata()?.len();
        let remaining_in_seg = seg_size.saturating_sub(seg_offset) as usize;
        let to_read = buf.len().min(remaining_in_seg);

        let n = file.read(&mut buf[..to_read])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for SplitRawReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(off) => off,
            SeekFrom::End(delta) => (self.total_size as i64 + delta).max(0) as u64,
            SeekFrom::Current(delta) => (self.pos as i64 + delta).max(0) as u64,
        };
        self.pos = new_pos;
        Ok(self.pos)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Partition discovery
// ─────────────────────────────────────────────────────────────────────────────

/// Scan the disk image at `path` and return all supported partitions found.
///
/// Detects NTFS and EXT4 filesystems. Handles bare partition images,
/// GPT, and MBR (including extended/logical partitions).
pub fn find_partitions(path: &Path) -> Result<Vec<PartitionInfo>> {
    let mut img = open_image(path)?;

    let mut sector0 = [0u8; 512];
    img.seek(SeekFrom::Start(0)).context("seek to sector 0 failed")?;
    img.read_exact(&mut sector0).context("read sector 0 failed")?;

    // 1. Bare filesystem at offset 0 — no MBR/GPT wrapper.
    if &sector0[3..11] == NTFS_OEM_ID {
        let size = img.seek(SeekFrom::End(0)).unwrap_or(0);
        info!("Image is a bare NTFS partition; size = {} bytes", size);
        return Ok(vec![PartitionInfo { offset: 0, size, filesystem: FilesystemType::Ntfs }]);
    }

    // Check for bare EXT4 at offset 0.
    {
        let mut magic = [0u8; 2];
        if img.seek(SeekFrom::Start(EXT4_MAGIC_OFFSET)).is_ok()
            && img.read_exact(&mut magic).is_ok()
            && magic == EXT4_MAGIC
        {
            let size = img.seek(SeekFrom::End(0)).unwrap_or(0);
            info!("Image is a bare EXT4 partition; size = {} bytes", size);
            return Ok(vec![PartitionInfo { offset: 0, size, filesystem: FilesystemType::Ext4 }]);
        }
    }

    // 2. Require 0x55AA.
    if sector0[510..512] != MBR_BOOT_SIG {
        return Err(anyhow!(
            "unrecognised disk format: sector 0 is not an NTFS VBR, MBR, or GPT \
             protective MBR (no 0x55AA boot signature at bytes 510-511). \
             The image may use an unsupported format such as Ex01, L01, S01, \
             or a non-NTFS filesystem."
        ));
    }

    // 3. GPT.
    let first_type = sector0[PARTITION_TABLE_OFFSET + 4];
    if first_type == PT_GPT_PROTECTIVE {
        let partitions = find_gpt_partitions(&mut *img)?;
        if !partitions.is_empty() {
            return Ok(partitions);
        }
        log::warn!("GPT protective MBR found but no NTFS Basic Data partitions detected in the GPT table");
        return Ok(vec![]);
    }

    // 4. MBR.
    find_mbr_partitions(&mut *img, &sector0)
}

fn find_mbr_partitions(img: &mut dyn ReadSeek, mbr: &[u8]) -> Result<Vec<PartitionInfo>> {
    let mut partitions = Vec::new();
    let mut extended_lba: Option<u64> = None;

    for i in 0..PARTITION_COUNT {
        let off = PARTITION_TABLE_OFFSET + i * PARTITION_ENTRY_SIZE;
        let entry = &mbr[off..off + PARTITION_ENTRY_SIZE];
        let part_type = entry[4];
        if part_type == 0 || part_type == PT_GPT_PROTECTIVE {
            continue;
        }
        let lba_start = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]) as u64;
        let sector_count = u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]) as u64;
        if lba_start == 0 || sector_count == 0 { continue; }

        if part_type == PT_EXTENDED_CHS || part_type == PT_EXTENDED_LBA || part_type == PT_EXTENDED_LINUX {
            extended_lba = Some(lba_start);
            continue;
        }
        let byte_offset = lba_start * SECTOR_SIZE;
        let byte_size = sector_count * SECTOR_SIZE;
        if let Some(fs) = detect_filesystem(img, byte_offset) {
            partitions.push(PartitionInfo { offset: byte_offset, size: byte_size, filesystem: fs });
        }
    }

    if let Some(ext_start) = extended_lba {
        let mut ebr_lba = ext_start;
        for _ in 0..64 {
            let ebr_offset = ebr_lba * SECTOR_SIZE;
            let mut ebr = [0u8; 512];
            if img.seek(SeekFrom::Start(ebr_offset)).is_err() || img.read_exact(&mut ebr).is_err() {
                break;
            }
            if ebr[510] != 0x55 || ebr[511] != 0xAA { break; }

            let rel0_start = u32::from_le_bytes([ebr[454], ebr[455], ebr[456], ebr[457]]) as u64;
            let rel0_count = u32::from_le_bytes([ebr[458], ebr[459], ebr[460], ebr[461]]) as u64;
            if rel0_start > 0 && rel0_count > 0 {
                let byte_offset = (ebr_lba + rel0_start) * SECTOR_SIZE;
                let byte_size = rel0_count * SECTOR_SIZE;
                if let Some(fs) = detect_filesystem(img, byte_offset) {
                    partitions.push(PartitionInfo { offset: byte_offset, size: byte_size, filesystem: fs });
                }
            }

            let next_rel = u32::from_le_bytes([ebr[470], ebr[471], ebr[472], ebr[473]]) as u64;
            if next_rel == 0 { break; }
            ebr_lba = ext_start + next_rel;
        }
    }

    if partitions.is_empty() {
        log::warn!(
            "MBR partition table found but no supported filesystems detected. \
             The disk may use dynamic volumes (LDM), BitLocker, FAT32, or another \
             unsupported filesystem."
        );
    }

    Ok(partitions)
}

fn find_gpt_partitions(img: &mut dyn ReadSeek) -> Result<Vec<PartitionInfo>> {
    let mut partitions = Vec::new();

    let mut hdr = [0u8; 92];
    img.seek(SeekFrom::Start(SECTOR_SIZE)).context("seek to GPT header failed")?;
    img.read_exact(&mut hdr).context("read GPT header failed")?;

    if &hdr[0..8] != GPT_SIGNATURE {
        return Err(anyhow!("invalid GPT signature"));
    }

    let part_entry_lba = u64::from_le_bytes(hdr[72..80].try_into().unwrap());
    let num_entries   = u32::from_le_bytes(hdr[80..84].try_into().unwrap());
    let entry_size    = u32::from_le_bytes(hdr[84..88].try_into().unwrap()) as usize;

    if entry_size < 128 {
        return Err(anyhow!("GPT partition entry size {} is too small", entry_size));
    }

    let table_offset = part_entry_lba * SECTOR_SIZE;
    let mut entry_buf = vec![0u8; entry_size];

    for i in 0..num_entries.min(128) {
        let entry_offset = table_offset + i as u64 * entry_size as u64;
        img.seek(SeekFrom::Start(entry_offset))
            .with_context(|| format!("seek to GPT entry {} failed", i))?;
        img.read_exact(&mut entry_buf)
            .with_context(|| format!("read GPT entry {} failed", i))?;

        if entry_buf[0..16].iter().all(|&b| b == 0) { continue; }
        if entry_buf[0..16] != GPT_BASIC_DATA_GUID { continue; }

        let start_lba = u64::from_le_bytes(entry_buf[32..40].try_into().unwrap());
        let end_lba   = u64::from_le_bytes(entry_buf[40..48].try_into().unwrap());
        let byte_offset = start_lba * SECTOR_SIZE;
        let byte_size   = (end_lba.saturating_sub(start_lba) + 1) * SECTOR_SIZE;

        if let Some(fs) = detect_filesystem(img, byte_offset) {
            partitions.push(PartitionInfo { offset: byte_offset, size: byte_size, filesystem: fs });
        }
    }

    Ok(partitions)
}

// ─────────────────────────────────────────────────────────────────────────────
// PartitionReader
// ─────────────────────────────────────────────────────────────────────────────

/// A `Read + Seek` wrapper that presents a single partition as a standalone
/// stream starting at byte 0. All positions are relative to the partition.
pub struct PartitionReader<R: Read + Seek> {
    inner: R,
    base: u64,
    size: u64,
    pos: u64,
}

impl<R: Read + Seek> PartitionReader<R> {
    pub fn new(mut inner: R, base: u64, size: u64) -> std::io::Result<Self> {
        inner.seek(SeekFrom::Start(base))?;
        Ok(Self { inner, base, size, pos: 0 })
    }
}

impl<R: Read + Seek> Read for PartitionReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.size.saturating_sub(self.pos) as usize;
        if remaining == 0 { return Ok(0); }
        let limit = buf.len().min(remaining);
        let n = self.inner.read(&mut buf[..limit])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for PartitionReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_rel = match pos {
            SeekFrom::Start(off) => {
                self.inner.seek(SeekFrom::Start(self.base + off))?;
                off
            }
            SeekFrom::Current(delta) => {
                let abs = self.inner.seek(SeekFrom::Current(delta))?;
                abs.saturating_sub(self.base)
            }
            SeekFrom::End(delta) => {
                let target = (self.size as i64 + delta).max(0) as u64;
                self.inner.seek(SeekFrom::Start(self.base + target))?;
                target
            }
        };
        self.pos = new_rel;
        Ok(new_rel)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
