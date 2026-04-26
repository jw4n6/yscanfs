//! Filesystem walkers: NTFS (including ADS) and EXT4.
//!
//! Both walkers use an iterative (non-recursive) traversal to avoid stack
//! overflows on deeply nested directory trees, and feed a callback immediately
//! so file data is not retained after scanning.

use std::collections::HashSet;
use std::io::{Read, Seek, SeekFrom};

use anyhow::Result;
use chrono::{DateTime, Utc};
use indicatif::ProgressBar;
use log::warn;
use ntfs::structured_values::NtfsFileNamespace;
use ntfs::{Ntfs, NtfsAttributeType};

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/// A single file yielded during a filesystem walk.
pub struct FileEntry {
    /// Full path within the filesystem.
    /// For NTFS, ADS entries use the format `\path\to\file:StreamName`.
    /// For EXT4, paths use forward-slash separators (e.g. `/usr/bin/bash`).
    pub path: String,
    /// UTC timestamp of the file. For NTFS this is the `$STANDARD_INFORMATION`
    /// creation time. For EXT4 this is Unix epoch (timestamps not yet exposed
    /// by ext4-view; will be updated in a future release).
    pub creation_time: DateTime<Utc>,
    /// Raw file content (up to `max_size` bytes).
    pub data: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Walk every regular file (and its Alternate Data Streams) in the NTFS
/// partition presented by `fs`.
///
/// For each file `callback` is invoked immediately with a [`FileEntry`].
/// The data is not retained after the callback returns, keeping memory usage
/// constant regardless of image size.
///
/// Files larger than `max_size` bytes are skipped and logged at `warn` level.
/// Per-file errors are also logged at `warn` level and skipped.
pub fn walk_ntfs<R, F>(
    fs: &mut R,
    max_size: u64,
    pb: &ProgressBar,
    mut callback: F,
) -> Result<()>
where
    R: std::io::Read + std::io::Seek,
    F: FnMut(FileEntry),
{
    let ntfs = Ntfs::new(fs).map_err(|e| anyhow::anyhow!("NTFS init failed: {}", e))?;

    let root_record = {
        let root = ntfs
            .root_directory(fs)
            .map_err(|e| anyhow::anyhow!("cannot open NTFS root directory: {}", e))?;
        root.file_record_number()
    };

    let mut stack: Vec<(u64, String)> = vec![(root_record, String::new())];
    let mut visited: HashSet<u64> = HashSet::new();
    visited.insert(root_record);

    // files_scanned counts unique files (not individual ADS streams).
    let mut files_scanned: u64 = 0;

    while let Some((record_num, path)) = stack.pop() {
        let file = match ntfs.file(fs, record_num) {
            Ok(f) => f,
            Err(e) => {
                warn!("cannot open record {}: {}", record_num, e);
                continue;
            }
        };

        if file.is_directory() {
            // ── Directory: push children onto the stack ───────────────────
            let index = match file.directory_index(fs) {
                Ok(idx) => idx,
                Err(e) => {
                    warn!("cannot read dir index at '{}': {}", path, e);
                    continue;
                }
            };

            let mut iter = index.entries();
            let mut children: Vec<(u64, String)> = Vec::new();

            while let Some(entry) = iter.next(fs) {
                let entry = match entry {
                    Ok(e) => e,
                    Err(e) => {
                        warn!("dir entry error: {}", e);
                        continue;
                    }
                };

                let child_record = entry.file_reference().file_record_number();

                if child_record < 24 || visited.contains(&child_record) {
                    continue;
                }

                let child_name = match entry.key() {
                    Some(Ok(ref fname)) => {
                        if fname.namespace() == NtfsFileNamespace::Dos {
                            continue;
                        }
                        fname.name().to_string_lossy().to_string()
                    }
                    Some(Err(e)) => {
                        warn!("fname error: {}", e);
                        continue;
                    }
                    None => continue,
                };

                let child_path = if path.is_empty() {
                    format!("\\{}", child_name)
                } else {
                    format!("{}\\{}", path, child_name)
                };

                visited.insert(child_record);
                children.push((child_record, child_path));
            }

            for child in children.into_iter().rev() {
                stack.push(child);
            }
        } else {
            // ── Regular file: read each $DATA stream and yield immediately ─

            let creation_time = match file.info() {
                Ok(si) => ntfs_time_to_utc(si.creation_time()),
                Err(e) => {
                    warn!("no $STANDARD_INFO for '{}': {}", path, e);
                    continue;
                }
            };

            // Enumerate all $DATA attributes — unnamed stream + any ADS.
            let mut attr_iter = file.attributes();
            while let Some(item) = attr_iter.next(fs) {
                let item = match item {
                    Ok(i) => i,
                    Err(e) => {
                        warn!("attribute error for '{}': {}", path, e);
                        continue;
                    }
                };

                let attribute = match item.to_attribute() {
                    Ok(a) => a,
                    Err(e) => {
                        warn!("to_attribute error for '{}': {}", path, e);
                        continue;
                    }
                };

                // Only $DATA attributes.
                match attribute.ty() {
                    Ok(NtfsAttributeType::Data) => {}
                    _ => continue,
                }

                // Build stream path: bare path for unnamed, path:name for ADS.
                let stream_name = match attribute.name() {
                    Ok(n) => n.to_string_lossy().to_string(),
                    Err(e) => {
                        warn!("stream name error for '{}': {}", path, e);
                        continue;
                    }
                };

                let stream_path = if stream_name.is_empty() {
                    path.clone()
                } else {
                    format!("{}:{}", path, stream_name)
                };

                let value = match attribute.value(fs) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("value error for '{}': {}", stream_path, e);
                        continue;
                    }
                };

                let file_len = value.len();

                // Skip empty streams.
                if file_len == 0 {
                    continue;
                }

                if file_len > max_size {
                    warn!(
                        "skipping '{}' ({} MB > {} MB limit)",
                        stream_path,
                        file_len / 1_048_576,
                        max_size / 1_048_576,
                    );
                    continue;
                }

                // Read content, scan, discard.
                let mut data: Vec<u8> = Vec::with_capacity(file_len as usize);
                let mut attached = value.attach(fs);
                if let Err(e) = attached.read_to_end(&mut data) {
                    warn!("read error for '{}': {}", stream_path, e);
                    continue;
                }
                drop(attached);

                // Increment the file counter only for the primary (unnamed)
                // stream so ADS entries don't inflate the count.
                if stream_name.is_empty() {
                    files_scanned += 1;
                    let display_name = path.rsplit('\\').next().unwrap_or(&path);
                    pb.set_message(format!(
                        "{} files scanned  ∙  {}",
                        files_scanned, display_name
                    ));
                }

                callback(FileEntry {
                    path: stream_path,
                    creation_time,
                    data,
                });
            }
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Convert an NTFS 100-nanosecond timestamp (since 1601-01-01) to `DateTime<Utc>`.
fn ntfs_time_to_utc(nt: ntfs::NtfsTime) -> DateTime<Utc> {
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000u64;
    let ts = nt.nt_timestamp();
    if ts < EPOCH_DIFF {
        return DateTime::UNIX_EPOCH;
    }
    let intervals = ts - EPOCH_DIFF;
    let secs = (intervals / 10_000_000) as i64;
    let nanos = ((intervals % 10_000_000) * 100) as u32;
    DateTime::from_timestamp(secs, nanos).unwrap_or(DateTime::UNIX_EPOCH)
}

// ─────────────────────────────────────────────────────────────────────────────
// EXT4 walker
// ─────────────────────────────────────────────────────────────────────────────

/// Adapter that implements [`ext4_view::Ext4Read`] over any [`crate::disk::ReadSeek`].
///
/// `start_byte` is an absolute offset within the partition reader — byte 0
/// of the adapter maps to the start of the partition on disk.
struct Ext4ReadAdapter {
    inner: Box<dyn crate::disk::ReadSeek>,
}

impl ext4_view::Ext4Read for Ext4ReadAdapter {
    fn read(
        &mut self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        self.inner.seek(SeekFrom::Start(start_byte))
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        self.inner.read_exact(dst)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        Ok(())
    }
}

/// Walk every regular file in the EXT4 partition presented by `reader`.
///
/// Uses an explicit stack for iterative traversal (no recursion). For each
/// regular file `callback` is invoked with a [`FileEntry`]. Files larger than
/// `max_size` are skipped and logged. Per-file errors are logged and skipped.
///
/// **Note on timestamps:** ext4-view 0.9.3 does not expose inode timestamps
/// via the `Metadata` struct, so `creation_time` is set to Unix epoch.
/// This will be updated when a future version of ext4-view exposes timestamps.
pub fn walk_ext4<R, F>(
    reader: R,
    max_size: u64,
    pb: &ProgressBar,
    mut callback: F,
) -> Result<()>
where
    R: crate::disk::ReadSeek + 'static,
    F: FnMut(FileEntry),
{
    let adapter = Ext4ReadAdapter { inner: Box::new(reader) };

    let fs = ext4_view::Ext4::load(Box::new(adapter))
        .map_err(|e| anyhow::anyhow!("EXT4 init failed: {}", e))?;

    // Iterative directory walk using an explicit path stack.
    let mut stack: Vec<String> = vec!["/".to_string()];
    let mut files_scanned: u64 = 0;

    while let Some(dir_path) = stack.pop() {
        let entries = match fs.read_dir(&dir_path) {
            Ok(e) => e,
            Err(e) => {
                warn!("cannot read EXT4 directory '{}': {}", dir_path, e);
                continue;
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    warn!("EXT4 dir entry error in '{}': {}", dir_path, e);
                    continue;
                }
            };

            // Get the name as a str to check for . and ..
            let name = match entry.file_name().as_str() {
                Ok(n) => n.to_string(),
                Err(_) => {
                    warn!("non-UTF-8 filename in '{}'", dir_path);
                    continue;
                }
            };

            if name == "." || name == ".." {
                continue;
            }

            // Build path string.
            let path_str = match entry.path().to_str() {
                Ok(p) => p.to_string(),
                Err(_) => {
                    warn!("non-UTF-8 path under '{}'", dir_path);
                    continue;
                }
            };

            // Use file_type() from DirEntry directly — avoids a second inode read.
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(e) => {
                    warn!("cannot get file type for '{}': {}", path_str, e);
                    continue;
                }
            };

            if file_type.is_dir() {
                stack.push(path_str);
                continue;
            }

            // Skip symlinks, devices, pipes, sockets.
            if !file_type.is_regular_file() {
                continue;
            }

            // Get file size from metadata.
            let file_size = match fs.metadata(&path_str) {
                Ok(m) => m.len(),
                Err(e) => {
                    warn!("cannot stat EXT4 '{}': {}", path_str, e);
                    continue;
                }
            };

            if file_size == 0 {
                continue;
            }

            if file_size > max_size {
                warn!(
                    "skipping '{}' ({} MB > {} MB limit)",
                    path_str,
                    file_size / 1_048_576,
                    max_size / 1_048_576,
                );
                continue;
            }

            let data = match fs.read(&path_str) {
                Ok(d) => d,
                Err(e) => {
                    warn!("read error for EXT4 '{}': {}", path_str, e);
                    continue;
                }
            };

            // ext4-view 0.9.3 does not expose inode timestamps via Metadata;
            // use Unix epoch as a placeholder until a future version adds them.
            let creation_time = DateTime::UNIX_EPOCH;

            files_scanned += 1;
            let display_name = path_str.rsplit('/').next().unwrap_or(&path_str).to_string();
            pb.set_message(format!(
                "{} files scanned  \u{22c5}  {}",
                files_scanned, display_name
            ));

            callback(FileEntry {
                path: path_str,
                creation_time,
                data,
            });
        }
    }

    Ok(())
}
