//! VSS (Volume Shadow Copy) snapshot enumeration and scanning.
//!
//! Uses the `vshadow` crate to parse VSS structures directly from NTFS
//! partition data — no Windows APIs required, works on all platforms.
//!
//! # How VSS works in disk images
//!
//! Windows writes VSS structures into a reserved area of the NTFS volume
//! starting at offset 0x1E00. Each snapshot (store) is a point-in-time copy
//! of the volume: changed blocks are stored in the VSS area, unchanged blocks
//! are read from the live volume. `VssStoreReader` reassembles this
//! transparently and presents the snapshot as a seekable byte stream
//! indistinguishable from a normal NTFS volume image.

use std::path::Path;

use anyhow::Result;
use chrono::{DateTime, TimeZone, Utc};
use indicatif::ProgressBar;
use vshadow::VssVolume;

use crate::disk::{open_image, find_partitions, FilesystemType, PartitionReader};
use crate::fs_walker::{walk_ntfs, FileEntry};

/// Metadata about a single VSS snapshot found on a partition.
#[derive(Debug, Clone)]
pub struct VssSnapshot {
    /// 1-based human display index within this partition.
    pub index: usize,
    /// Creation timestamp (UTC).
    pub created: DateTime<Utc>,
    /// Volume size at snapshot time (bytes).
    pub volume_size: u64,
}

/// List all VSS snapshots on all supported partitions of `image_path`.
///
/// Returns a `Vec<(partition_index, VssSnapshot)>` — the partition index
/// is the 0-based index into the partitions returned by `find_partitions`.
pub fn list_snapshots(image_path: &Path) -> Result<Vec<(usize, VssSnapshot)>> {
    let partitions = find_partitions(image_path)?;
    let mut result = Vec::new();

    for (part_idx, partition) in partitions.iter().enumerate() {
        // VSS is only present on NTFS volumes.
        if partition.filesystem != FilesystemType::Ntfs {
            continue;
        }

        let img = open_image(image_path)?;
        let mut reader = PartitionReader::new(img, partition.offset, partition.size)
            .map_err(|e| anyhow::anyhow!("PartitionReader: {}", e))?;

        let volume = match VssVolume::new(&mut reader) {
            Ok(v) => v,
            Err(e) => {
                log::debug!("VSS parse failed for partition {}: {}", part_idx, e);
                continue;
            }
        };

        let count = volume.store_count();
        if count == 0 {
            log::debug!("partition {} has no VSS snapshots", part_idx);
            continue;
        }

        for i in 0..count {
            let info = match volume.store_info(i) {
                Ok(s) => s,
                Err(e) => {
                    log::warn!("VSS store {} info failed: {}", i, e);
                    continue;
                }
            };

            let created = filetime_to_utc(info.creation_time);
            result.push((
                part_idx,
                VssSnapshot {
                    index: i + 1,
                    created,
                    volume_size: info.volume_size,
                },
            ));
        }
    }

    Ok(result)
}

/// Walk every file in all VSS snapshots of the given NTFS partition, calling
/// `callback` for each file entry.
///
/// `partition_offset` and `partition_size` identify the NTFS partition within
/// the disk image. `snapshot_label` is used for progress display.
pub fn walk_vss_snapshots<F>(
    image_path: &Path,
    partition_offset: u64,
    partition_size: u64,
    max_size: u64,
    pb: &ProgressBar,
    mut callback: F,
) -> Result<Vec<VssSnapshot>>
where
    F: FnMut(FileEntry, &VssSnapshot),
{
    let img = open_image(image_path)?;
    let mut reader = PartitionReader::new(img, partition_offset, partition_size)
        .map_err(|e| anyhow::anyhow!("PartitionReader: {}", e))?;

    let volume = match VssVolume::new(&mut reader) {
        Ok(v) => v,
        Err(e) => {
            log::debug!("no VSS on this partition: {}", e);
            return Ok(Vec::new());
        }
    };

    let count = volume.store_count();
    if count == 0 {
        return Ok(Vec::new());
    }

    log::info!("found {} VSS snapshot(s) on partition at offset {}", count, partition_offset);
    let mut snapshots = Vec::new();

    for i in 0..count {
        let info = match volume.store_info(i) {
            Ok(s) => s,
            Err(e) => {
                log::warn!("VSS store {} info failed: {}", i, e);
                continue;
            }
        };

        let created = filetime_to_utc(info.creation_time);
        let snapshot = VssSnapshot {
            index: i + 1,
            created,
            volume_size: info.volume_size,
        };

        pb.set_message(format!(
            "VSS snapshot {} of {}  (created {})",
            i + 1, count,
            created.format("%Y-%m-%d %H:%M:%S UTC")
        ));

        // Create a fresh reader for the store — VssStoreReader borrows mutably.
        let img2 = open_image(image_path)?;
        let mut reader2 = PartitionReader::new(img2, partition_offset, partition_size)
            .map_err(|e| anyhow::anyhow!("PartitionReader: {}", e))?;

        // Rebuild the VssVolume for this fresh reader (needed because
        // VssStoreReader<'a, R> borrows reader2 mutably for its lifetime).
        let volume2 = match VssVolume::new(&mut reader2) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("VSS volume re-parse failed for snapshot {}: {}", i, e);
                continue;
            }
        };

        let mut store_reader = match volume2.store_reader(&mut reader2, i) {
            Ok(r) => r,
            Err(e) => {
                log::warn!("VSS store {} reader failed: {}", i, e);
                continue;
            }
        };

        let snap_clone = snapshot.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            walk_ntfs(&mut store_reader, max_size, pb, |entry| {
                callback(entry, &snap_clone);
            })
        }));
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => log::warn!("VSS snapshot {} walk error: {}", i + 1, e),
            Err(_) => log::warn!(
                "VSS snapshot {} walk panicked — likely a compressed or corrupt \
                 NTFS attribute list (ntfs crate v0.4.0 limitation). \
                 Partial results preserved.",
                i + 1
            ),
        }

        snapshots.push(snapshot);
    }

    Ok(snapshots)
}

/// Convert a Windows FILETIME (100-ns intervals since 1601-01-01) to UTC.
fn filetime_to_utc(filetime: u64) -> DateTime<Utc> {
    if filetime == 0 {
        return DateTime::UNIX_EPOCH;
    }
    // Seconds since 1601-01-01 → subtract offset to get Unix epoch.
    const EPOCH_DIFF: u64 = 11_644_473_600;
    let secs = filetime / 10_000_000;
    if secs < EPOCH_DIFF {
        return DateTime::UNIX_EPOCH;
    }
    let unix_secs = secs - EPOCH_DIFF;
    Utc.timestamp_opt(unix_secs as i64, 0)
        .single()
        .unwrap_or(DateTime::UNIX_EPOCH)
}
