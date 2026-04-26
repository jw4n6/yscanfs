//! Disk-image access: format detection, EWF/raw/VHD/VHDX/VMDK readers,
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
const EWF_MAGIC: &[u8; 8]        = b"EVF\x09\x0D\x0A\xFF\x00";
const VHD_COOKIE: &[u8; 8]       = b"conectix";
const VHD_DYNAMIC_COOKIE: &[u8; 8] = b"cxsparse";

/// VHDX file identifier signature — first 8 bytes of every VHDX file.
const VHDX_SIGNATURE: &[u8; 8]   = b"vhdxfile";
/// VHDX header signature in each of the two 64-KB header structures.
const VHDX_HEADER_SIG: &[u8; 4]  = b"head";
/// VHDX region table signature.
const VHDX_REGION_SIG: &[u8; 4]  = b"regi";

/// VMDK sparse extent header magic ("KDMV" in little-endian).
const VMDK_SPARSE_MAGIC: u32      = 0x564D444B;

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
    /// Microsoft Virtual Hard Disk v1 — fixed or dynamic (.vhd)
    Vhd,
    /// Microsoft Virtual Hard Disk v2 — fixed or dynamic (.vhdx)
    Vhdx,
    /// VMware Virtual Machine Disk — flat (.vmdk; sparse detected and rejected)
    Vmdk,
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
            "vhd"  => return Ok(Self::Vhd),
            "vhdx" => return Ok(Self::Vhdx),
            "vmdk" => {
                // Distinguish flat (raw) from sparse VMDKs via magic bytes.
                return detect_vmdk(path);
            }
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

        // VHDX: "vhdxfile" at offset 0.
        if &magic[..8] == VHDX_SIGNATURE {
            return Ok(Self::Vhdx);
        }

        // VHD fixed: footer is at the very end, cookie at byte 0 of footer.
        // VHD dynamic: copy of footer at offset 0, dynamic header at 512.
        // Both start with "conectix".
        if &magic[..8] == VHD_COOKIE {
            return Ok(Self::Vhd);
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
            // VHD / VHDX
            "vhd", "vhdx",
            // VMDK (flat)
            "vmdk",
        ]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Image opening
// ─────────────────────────────────────────────────────────────────────────────

/// Open a disk image in read-only mode and return a boxed `Read + Seek`.
///
/// Supports EWF (.E01), raw/DD (.raw, .dd, .img, .bin), split raw (.001…),
/// VHD fixed/dynamic (.vhd), VHDX fixed/dynamic (.vhdx), and flat VMDK (.vmdk).
pub fn open_image(path: &Path) -> Result<Box<dyn ReadSeek>> {
    let fmt = ImageFormat::detect(path)?;
    match fmt {
        ImageFormat::Ewf => {
            let reader = ewf::EwfReader::open(path)
                .map_err(|e| anyhow!("cannot open EWF image '{}': {}", path.display(), e))?;
            Ok(Box::new(reader))
        }
        ImageFormat::Raw | ImageFormat::Vmdk => {
            // Flat VMDK and raw/DD images are both plain byte streams.
            let f = File::open(path)
                .with_context(|| format!("cannot open image '{}'", path.display()))?;
            Ok(Box::new(f))
        }
        ImageFormat::SplitRaw => {
            let reader = SplitRawReader::open(path)
                .with_context(|| format!("cannot open split raw image '{}'", path.display()))?;
            Ok(Box::new(reader))
        }
        ImageFormat::Vhd => {
            let reader = VhdReader::open(path)
                .with_context(|| format!("cannot open VHD image '{}'", path.display()))?;
            Ok(Box::new(reader))
        }
        ImageFormat::Vhdx => {
            let reader = VhdxReader::open(path)
                .with_context(|| format!("cannot open VHDX image '{}'", path.display()))?;
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
// VHD reader (fixed and dynamic)
// ─────────────────────────────────────────────────────────────────────────────

/// A read-only `Read + Seek` reader for VHD (Virtual Hard Disk) images.
///
/// Supports both **fixed** and **dynamic** VHD variants as specified in the
/// Microsoft VHD specification (https://download.microsoft.com/download/f/f/e/
/// ffef50a5-07dd-4cf8-aaa3-442c0673a029/Virtual%20Hard%20Disk%20Format%20Spec_10_18_06.doc).
///
/// **Fixed VHD**: raw sector data occupying the entire file, with a 512-byte
/// footer appended at the end. Disk size = file size − 512.
///
/// **Dynamic VHD**: a 512-byte footer copy at offset 0, a 1024-byte dynamic
/// disk header at offset 512, a BAT (Block Allocation Table), and variable-
/// size data blocks each preceded by a sector bitmap.
pub struct VhdReader {
    file: File,
    disk_type: VhdDiskType,
    disk_size: u64,
    pos: u64,
}

#[derive(Debug, Clone)]
enum VhdDiskType {
    Fixed,
    Dynamic {
        block_size: u64,    // bytes per block
        bat_offset: u64,    // absolute offset of BAT in file
    },
}

/// VHD disk type codes from the footer.
const VHD_TYPE_FIXED:   u32 = 2;
const VHD_TYPE_DYNAMIC: u32 = 3;
/// BAT entry indicating a sparse (unallocated) block.
const VHD_BAT_EMPTY: u32 = 0xFFFF_FFFF;
/// Size of the sector bitmap at the start of each dynamic block (rounded to
/// 512-byte sectors). For a 2 MB block with 512-byte sectors:
/// 2097152 / 512 = 4096 bits = 512 bytes → 1 sector bitmap sector.
const VHD_DEFAULT_BLOCK_SIZE: u64 = 2 * 1024 * 1024; // 2 MB

impl VhdReader {
    /// Open a VHD image in read-only mode.
    pub fn open(path: &Path) -> Result<Self> {
        let mut file = File::open(path)
            .with_context(|| format!("cannot open VHD '{}'", path.display()))?;

        let file_size = file.seek(SeekFrom::End(0))?;
        if file_size < 512 {
            return Err(anyhow!("'{}' is too small to be a VHD", path.display()));
        }

        // Read footer — either from the end (fixed) or offset 0 (dynamic copy).
        // We read the last 512 bytes first to identify fixed VHDs.
        let footer = Self::read_footer(&mut file, file_size)?;
        let disk_type_code = u32::from_be_bytes(footer[60..64].try_into().unwrap());
        let disk_size = u64::from_be_bytes(footer[40..48].try_into().unwrap());

        match disk_type_code {
            VHD_TYPE_FIXED => {
                Ok(Self {
                    file,
                    disk_type: VhdDiskType::Fixed,
                    disk_size,
                    pos: 0,
                })
            }
            VHD_TYPE_DYNAMIC => {
                // Dynamic header lives at offset 512.
                let mut dyn_hdr = [0u8; 1024];
                file.seek(SeekFrom::Start(512))?;
                file.read_exact(&mut dyn_hdr)
                    .context("cannot read VHD dynamic header")?;

                // Verify dynamic header cookie "cxsparse".
                if &dyn_hdr[0..8] != VHD_DYNAMIC_COOKIE {
                    return Err(anyhow!("'{}' has invalid VHD dynamic header cookie", path.display()));
                }

                let bat_offset = u64::from_be_bytes(dyn_hdr[16..24].try_into().unwrap());
                let block_size = u64::from_be_bytes(dyn_hdr[32..40].try_into().unwrap());
                let block_size = if block_size == 0 { VHD_DEFAULT_BLOCK_SIZE } else { block_size };

                Ok(Self {
                    file,
                    disk_type: VhdDiskType::Dynamic {
                        block_size,
                        bat_offset,
                    },
                    disk_size,
                    pos: 0,
                })
            }
            other => Err(anyhow!(
                "'{}' has unsupported VHD disk type {} (only fixed=2 and dynamic=3 are supported)",
                path.display(), other
            )),
        }
    }

    /// Read the 512-byte VHD footer and validate its cookie.
    fn read_footer(file: &mut File, file_size: u64) -> Result<[u8; 512]> {
        let mut footer = [0u8; 512];

        // Try footer at end of file first (fixed VHD).
        file.seek(SeekFrom::Start(file_size - 512))?;
        file.read_exact(&mut footer)?;

        if &footer[0..8] == VHD_COOKIE {
            return Ok(footer);
        }

        // Try footer copy at offset 0 (dynamic VHD).
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut footer)?;

        if &footer[0..8] == VHD_COOKIE {
            return Ok(footer);
        }

        Err(anyhow!("no valid VHD footer found (cookie mismatch)"))
    }

    /// Read `n` bytes from the current disk position, handling dynamic block
    /// lookups transparently. Returns the number of bytes actually read.
    fn read_at(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.disk_size.saturating_sub(self.pos) as usize;
        if remaining == 0 {
            return Ok(0);
        }
        let to_read = buf.len().min(remaining);

        match &self.disk_type.clone() {
            VhdDiskType::Fixed => {
                self.file.seek(SeekFrom::Start(self.pos))?;
                let n = self.file.read(&mut buf[..to_read])?;
                self.pos += n as u64;
                Ok(n)
            }
            VhdDiskType::Dynamic { block_size, bat_offset, .. } => {
                let block_size = *block_size;
                let bat_offset = *bat_offset;

                let block_idx = self.pos / block_size;
                let block_off = self.pos % block_size;

                // Read BAT entry for this block (4 bytes, big-endian, in sectors).
                let bat_entry_offset = bat_offset + block_idx * 4;
                self.file.seek(SeekFrom::Start(bat_entry_offset))?;
                let mut entry_bytes = [0u8; 4];
                self.file.read_exact(&mut entry_bytes)?;
                let bat_entry = u32::from_be_bytes(entry_bytes);

                if bat_entry == VHD_BAT_EMPTY {
                    // Sparse block — return zeroes.
                    let n = to_read.min((block_size - block_off) as usize);
                    buf[..n].fill(0);
                    self.pos += n as u64;
                    return Ok(n);
                }

                // BAT entry is the sector offset of the block's bitmap.
                // Data starts one bitmap-sector after the bitmap.
                let bitmap_sectors = ((block_size / SECTOR_SIZE) + 7) / 8 / SECTOR_SIZE;
                let bitmap_sectors = bitmap_sectors.max(1);
                let data_start = (bat_entry as u64 + bitmap_sectors) * SECTOR_SIZE;

                let read_offset = data_start + block_off;
                // Read at most to the end of this block.
                let bytes_left_in_block = block_size - block_off;
                let n = to_read.min(bytes_left_in_block as usize);

                self.file.seek(SeekFrom::Start(read_offset))?;
                let n = self.file.read(&mut buf[..n])?;
                self.pos += n as u64;
                Ok(n)
            }
        }
    }
}

impl Read for VhdReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.read_at(buf)
    }
}

impl Seek for VhdReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(off) => off,
            SeekFrom::End(delta) => (self.disk_size as i64 + delta).max(0) as u64,
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
// VMDK detection helper
// ─────────────────────────────────────────────────────────────────────────────

/// Detect VMDK subtype by inspecting the first 4 bytes.
///
/// VMware sparse/compressed VMDKs begin with the magic value 0x564D444B
/// ("KDMV" in little-endian). These require VMDK-aware parsing that yscanfs
/// does not yet support. Flat VMDKs (the `-flat.vmdk` data files produced by
/// FTK Imager, Magnet AXIOM, and `vmkfstools -i`) have no special header and
/// are treated as raw byte streams.
fn detect_vmdk(path: &Path) -> Result<ImageFormat> {
    let mut f = File::open(path)
        .with_context(|| format!("cannot open '{}' for VMDK detection", path.display()))?;
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic).unwrap_or(());
    let magic_u32 = u32::from_le_bytes(magic);
    if magic_u32 == VMDK_SPARSE_MAGIC {
        return Err(anyhow!(
            "'{}' is a sparse/compressed VMDK. \
             yscanfs supports flat VMDKs (-flat.vmdk) only. \
             Convert with: vmware-vdiskmanager -r input.vmdk -t 0 flat.vmdk",
            path.display()
        ));
    }
    // Flat VMDK — plain raw bytes.
    Ok(ImageFormat::Vmdk)
}

// ─────────────────────────────────────────────────────────────────────────────
// VHDX reader
//
// Implements read-only access to VHDX v1 images (both fixed and dynamic).
// Reference: [MS-VHDX] Open Specification, revision 9.0.
//
// File layout (all sections are 1 MB aligned):
//   [0x000000]  File Identifier  (1 MB)  — "vhdxfile" signature
//   [0x100000]  Header Section   (1 MB)  — two 64-KB headers; use highest seq
//   [0x200000]  Region Table     (1 MB)  — two 64-KB region tables
//   [variable]  Log region              — not used for read-only access
//   [variable]  Metadata region         — virtual disk size, block size, etc.
//   [variable]  BAT region              — block allocation table
//   [variable]  Data blocks             — actual disk content
// ─────────────────────────────────────────────────────────────────────────────

/// GUIDs for the two mandatory VHDX regions (little-endian byte order).
const VHDX_REGION_BAT_GUID: [u8; 16] = [
    0x66, 0x77, 0xC2, 0x2D, 0x23, 0xF6, 0x00, 0x42,
    0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD, 0x4A, 0x08,
];
const VHDX_REGION_METADATA_GUID: [u8; 16] = [
    0x06, 0xA2, 0x7C, 0x8B, 0x90, 0x47, 0x9A, 0x4B,
    0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F, 0x88, 0x6E,
];

/// VHDX metadata item GUIDs.
const VHDX_META_VIRTUAL_DISK_SIZE: [u8; 16] = [
    0x24, 0x42, 0xA5, 0x2F, 0x1B, 0xD6, 0x48, 0x76,
    0xB2, 0x11, 0x5D, 0xBE, 0xD8, 0x3B, 0xF4, 0xB8,
];
const VHDX_META_LOGICAL_SECTOR_SIZE: [u8; 16] = [
    0x1D, 0xBF, 0x41, 0x81, 0x6F, 0xA9, 0x09, 0x47,
    0xBA, 0x47, 0xF2, 0x33, 0xA8, 0xFA, 0xAB, 0x5F,
];
const VHDX_META_BLOCK_SIZE: [u8; 16] = [
    0x37, 0x67, 0xA1, 0xCA, 0x36, 0xFA, 0x43, 0x4D,
    0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44, 0xE7, 0x6B,
];

/// BAT entry payload block states.
const VHDX_BAT_PAYLOAD_NOT_PRESENT:    u64 = 0;
const VHDX_BAT_PAYLOAD_ZERO:           u64 = 2;
const VHDX_BAT_PAYLOAD_UNMAPPED:       u64 = 3;
const VHDX_BAT_PAYLOAD_FULLY_PRESENT:  u64 = 6;
const VHDX_BAT_PAYLOAD_PARTIALLY_PRESENT: u64 = 7;

/// Read-only reader for VHDX v1 disk images.
#[allow(dead_code)]
pub struct VhdxReader {
    file:         File,
    virtual_size: u64,       // total virtual disk bytes
    block_size:   u64,       // bytes per data block
    sector_size:  u64,       // logical sector size (512 or 4096)
    chunk_ratio:  u64,       // BAT entries between payload entries
    bat_offset:   u64,       // byte offset of BAT region in file
    bat:          Vec<u64>,  // loaded BAT entries
    pos:          u64,       // current virtual seek position
}

impl VhdxReader {
    /// Open and parse a VHDX file.
    pub fn open(path: &Path) -> Result<Self> {
        let mut f = File::open(path)
            .with_context(|| format!("cannot open VHDX '{}'", path.display()))?;

        // ── 1. Verify file identifier ──────────────────────────────────────
        let mut sig = [0u8; 8];
        f.seek(SeekFrom::Start(0))?;
        f.read_exact(&mut sig)?;
        if &sig != VHDX_SIGNATURE {
            return Err(anyhow!("not a VHDX file: missing 'vhdxfile' signature"));
        }

        // ── 2. Pick active header (highest valid sequence number) ──────────
        // Headers at 0x100000 and 0x140000; each starts with "head" + checksum
        // + sequence_number.
        let header1_seq = Self::read_header_seq(&mut f, 0x100000)?;
        let header2_seq = Self::read_header_seq(&mut f, 0x140000)?;
        // Pick whichever has the larger sequence number.
        // (If one is invalid, its sequence will be u64::MAX from the error path
        //  which we treat as less valid — but we silently fall back.)
        let _active_header_offset = if header1_seq >= header2_seq { 0x100000 } else { 0x140000 };

        // ── 3. Parse region table ──────────────────────────────────────────
        let (bat_offset, bat_length, metadata_offset) =
            Self::parse_region_table(&mut f, 0x200000)?;

        // ── 4. Parse metadata ──────────────────────────────────────────────
        let (virtual_size, block_size, sector_size) =
            Self::parse_metadata(&mut f, metadata_offset)?;

        if block_size == 0 || sector_size == 0 {
            return Err(anyhow!("VHDX metadata returned zero block/sector size"));
        }

        // chunk_ratio = (2^23 * logical_sector_size) / block_size
        let chunk_ratio = (1u64 << 23)
            .checked_mul(sector_size)
            .and_then(|v| v.checked_div(block_size))
            .ok_or_else(|| anyhow!("VHDX chunk_ratio overflow"))?;

        // ── 5. Load BAT ────────────────────────────────────────────────────
        let bat_entries = (bat_length / 8) as usize;
        let mut bat = vec![0u64; bat_entries];
        f.seek(SeekFrom::Start(bat_offset))?;
        let mut bat_bytes = vec![0u8; bat_length as usize];
        f.read_exact(&mut bat_bytes)?;
        for (i, chunk) in bat_bytes.chunks_exact(8).enumerate() {
            bat[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }

        log::info!(
            "VHDX: virtual_size={} GB, block_size={} MB, sector_size={}, \
             chunk_ratio={}, bat_entries={}",
            virtual_size / (1 << 30),
            block_size / (1 << 20),
            sector_size,
            chunk_ratio,
            bat_entries,
        );

        Ok(Self {
            file: f,
            virtual_size,
            block_size,
            sector_size,
            chunk_ratio,
            bat_offset,
            bat,
            pos: 0,
        })
    }

    /// Read the sequence number from a header at `offset`.
    /// Returns 0 if the header signature is wrong.
    fn read_header_seq(f: &mut File, offset: u64) -> Result<u64> {
        let mut buf = [0u8; 16];
        f.seek(SeekFrom::Start(offset))?;
        f.read_exact(&mut buf)?;
        if &buf[..4] != VHDX_HEADER_SIG { return Ok(0); }
        // Sequence number is at offset 8 in the header, 8 bytes.
        Ok(u64::from_le_bytes(buf[8..16].try_into().unwrap()))
    }

    /// Parse the first valid region table at `offset`.
    /// Returns (bat_file_offset, bat_length, metadata_file_offset).
    fn parse_region_table(f: &mut File, offset: u64) -> Result<(u64, u64, u64)> {
        let mut buf = [0u8; 65536];
        f.seek(SeekFrom::Start(offset))?;
        f.read_exact(&mut buf)?;

        if &buf[..4] != VHDX_REGION_SIG {
            // Try second region table at offset + 0x100000.
            f.seek(SeekFrom::Start(offset + 0x100000))?;
            f.read_exact(&mut buf)?;
            if &buf[..4] != VHDX_REGION_SIG {
                return Err(anyhow!("no valid VHDX region table found"));
            }
        }

        let entry_count = u32::from_le_bytes(buf[8..12].try_into().unwrap()) as usize;
        let entry_count = entry_count.min(2048); // sanity cap

        let mut bat_offset    = 0u64;
        let mut bat_length    = 0u64;
        let mut meta_offset   = 0u64;

        for i in 0..entry_count {
            let base = 16 + i * 32;
            if base + 32 > buf.len() { break; }

            let guid = &buf[base..base + 16];
            let file_offset = u64::from_le_bytes(buf[base + 16..base + 24].try_into().unwrap());
            let length      = u32::from_le_bytes(buf[base + 24..base + 28].try_into().unwrap()) as u64;

            if guid == VHDX_REGION_BAT_GUID {
                bat_offset = file_offset;
                bat_length = length;
            } else if guid == VHDX_REGION_METADATA_GUID {
                meta_offset = file_offset;
            }
        }

        if bat_offset == 0 || meta_offset == 0 {
            return Err(anyhow!("VHDX region table missing BAT or Metadata region"));
        }

        Ok((bat_offset, bat_length, meta_offset))
    }

    /// Parse the VHDX metadata section.
    /// Returns (virtual_disk_size, block_size, logical_sector_size).
    fn parse_metadata(f: &mut File, meta_offset: u64) -> Result<(u64, u64, u64)> {
        // Metadata table: 64KB header + entries.
        let mut table = [0u8; 65536];
        f.seek(SeekFrom::Start(meta_offset))?;
        f.read_exact(&mut table)?;

        // Table header: 8-byte sig "metadata", 2 bytes reserved, 2 bytes entry_count.
        if &table[..8] != b"metadata" {
            return Err(anyhow!("VHDX metadata table signature mismatch"));
        }
        let entry_count = u16::from_le_bytes(table[10..12].try_into().unwrap()) as usize;
        let entry_count = entry_count.min(2047); // spec max

        let mut virtual_size = 0u64;
        let mut block_size   = 0u64;
        let mut sector_size  = 512u64; // default

        for i in 0..entry_count {
            let base = 32 + i * 32;
            if base + 32 > table.len() { break; }

            let guid   = &table[base..base + 16];
            let offset = u32::from_le_bytes(table[base + 16..base + 20].try_into().unwrap()) as usize;
            let length = u32::from_le_bytes(table[base + 20..base + 24].try_into().unwrap()) as usize;

            if offset + length > table.len() { continue; }
            let data = &table[offset..offset + length];

            if guid == VHDX_META_VIRTUAL_DISK_SIZE && data.len() >= 8 {
                virtual_size = u64::from_le_bytes(data[..8].try_into().unwrap());
            } else if guid == VHDX_META_BLOCK_SIZE && data.len() >= 4 {
                block_size = u32::from_le_bytes(data[..4].try_into().unwrap()) as u64;
            } else if guid == VHDX_META_LOGICAL_SECTOR_SIZE && data.len() >= 4 {
                sector_size = u32::from_le_bytes(data[..4].try_into().unwrap()) as u64;
            }
        }

        Ok((virtual_size, block_size, sector_size))
    }

    /// Translate a virtual byte offset into a file byte offset using the BAT.
    /// Returns `None` for unmapped/zeroed blocks (caller should return zeros).
    fn resolve_offset(&self, virtual_offset: u64) -> Option<u64> {
        if virtual_offset >= self.virtual_size { return None; }

        let block_index = virtual_offset / self.block_size;
        let offset_in_block = virtual_offset % self.block_size;

        // BAT index for this payload block:
        // Groups of (chunk_ratio + 1): [payload, sb, sb, ..., payload, sb, ...]
        let bat_index = block_index * (self.chunk_ratio + 1);
        let bat_entry = *self.bat.get(bat_index as usize)?;
        let state = bat_entry & 0x7;

        match state {
            VHDX_BAT_PAYLOAD_FULLY_PRESENT | VHDX_BAT_PAYLOAD_PARTIALLY_PRESENT => {
                // FileOffsetMB is bits 63:20; offset in file = that value << 20.
                let file_base = bat_entry & !0xFFFFF; // clear lower 20 bits
                Some(file_base + offset_in_block)
            }
            VHDX_BAT_PAYLOAD_NOT_PRESENT
            | VHDX_BAT_PAYLOAD_ZERO
            | VHDX_BAT_PAYLOAD_UNMAPPED => None,
            _ => None,
        }
    }
}

impl Read for VhdxReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.virtual_size || buf.is_empty() {
            return Ok(0);
        }

        // Clamp to the block boundary so we never cross a BAT entry in one read.
        let block_end = (self.pos / self.block_size + 1) * self.block_size;
        let max_read  = (block_end - self.pos).min(self.virtual_size - self.pos) as usize;
        let to_read   = buf.len().min(max_read);

        match self.resolve_offset(self.pos) {
            Some(file_offset) => {
                self.file.seek(SeekFrom::Start(file_offset))
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                let n = self.file.read(&mut buf[..to_read])?;
                self.pos += n as u64;
                Ok(n)
            }
            None => {
                // Unmapped/zeroed block — return zeros.
                buf[..to_read].fill(0);
                self.pos += to_read as u64;
                Ok(to_read)
            }
        }
    }
}

impl Seek for VhdxReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.pos = match pos {
            SeekFrom::Start(off)    => off,
            SeekFrom::End(delta)    => (self.virtual_size as i64 + delta).max(0) as u64,
            SeekFrom::Current(delta) => (self.pos as i64 + delta).max(0) as u64,
        };
        Ok(self.pos)
    }
}
