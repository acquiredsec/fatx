//! Deleted file detection in FAT filesystems.
//!
//! FAT marks deleted directory entries by replacing the first byte of the
//! filename with 0xE5. This module scans raw directory data to find these
//! entries and attempts to recover file metadata.

use serde::Serialize;
use std::io::{Read, Seek, SeekFrom};

/// A deleted file entry recovered from raw directory data.
#[derive(Debug, Clone, Serialize)]
pub struct DeletedEntry {
    /// Original filename (first char replaced with '?')
    pub name: String,
    /// Short 8.3 name with first byte as '?'
    pub short_name: String,
    /// Was this a directory?
    pub is_directory: bool,
    /// File size from directory entry (may be stale)
    pub size: u32,
    /// First cluster number
    pub first_cluster: u32,
    /// Byte offset of this entry in the image
    pub offset: u64,
    /// Modified timestamp
    pub modified: String,
    /// Created timestamp
    pub created: String,
}

/// Scan raw bytes for deleted FAT directory entries (first byte = 0xE5).
/// `data` should be the raw directory cluster data.
/// `base_offset` is the absolute offset in the image for reporting.
pub fn scan_deleted_entries(data: &[u8], base_offset: u64) -> Vec<DeletedEntry> {
    let mut entries = Vec::new();
    let entry_size = 32;

    let mut i = 0;
    while i + entry_size <= data.len() {
        let entry = &data[i..i + entry_size];

        // Check if this is a deleted entry (first byte = 0xE5)
        if entry[0] == 0xE5 {
            // Skip LFN entries (attribute byte = 0x0F)
            let attr = entry[11];
            if attr == 0x0F {
                i += entry_size;
                continue;
            }

            // Parse the 8.3 short filename
            let mut name_bytes = [0u8; 11];
            name_bytes.copy_from_slice(&entry[0..11]);
            name_bytes[0] = b'?'; // Replace deleted marker with ?

            let base_name: String = name_bytes[0..8].iter()
                .map(|&b| b as char)
                .collect::<String>()
                .trim_end()
                .to_string();
            let ext: String = name_bytes[8..11].iter()
                .map(|&b| b as char)
                .collect::<String>()
                .trim_end()
                .to_string();

            let short_name = if ext.is_empty() {
                base_name.clone()
            } else {
                format!("{}.{}", base_name, ext)
            };

            let is_dir = attr & 0x10 != 0;
            let size = u32::from_le_bytes([entry[28], entry[29], entry[30], entry[31]]);

            // First cluster: high 2 bytes at offset 20, low 2 bytes at offset 26
            let cluster_hi = u16::from_le_bytes([entry[20], entry[21]]) as u32;
            let cluster_lo = u16::from_le_bytes([entry[26], entry[27]]) as u32;
            let first_cluster = (cluster_hi << 16) | cluster_lo;

            // Timestamps
            let modified = parse_fat_timestamp(
                u16::from_le_bytes([entry[22], entry[23]]),
                u16::from_le_bytes([entry[24], entry[25]]),
            );
            let created = parse_fat_timestamp(
                u16::from_le_bytes([entry[14], entry[15]]),
                u16::from_le_bytes([entry[16], entry[17]]),
            );

            entries.push(DeletedEntry {
                name: short_name.clone(),
                short_name,
                is_directory: is_dir,
                size,
                first_cluster,
                offset: base_offset + i as u64,
                modified,
                created,
            });
        } else if entry[0] == 0x00 {
            // End of directory entries
            break;
        }

        i += entry_size;
    }

    entries
}

/// Parse FAT time (2 bytes) and date (2 bytes) into a string.
fn parse_fat_timestamp(time: u16, date: u16) -> String {
    if date == 0 { return String::new(); }
    let year = ((date >> 9) & 0x7F) + 1980;
    let month = (date >> 5) & 0x0F;
    let day = date & 0x1F;
    let hour = (time >> 11) & 0x1F;
    let min = (time >> 5) & 0x3F;
    let sec = (time & 0x1F) * 2;
    format!("{}/{}/{} {}:{:02}:{:02}", month, day, year, hour, min, sec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_fat_timestamp() {
        // Date: 2024-07-27 = ((2024-1980)<<9) | (7<<5) | 27 = (44<<9)|(7<<5)|27 = 22528+224+27 = 22779
        // Time: 6:03:14 = (6<<11)|(3<<5)|(7) = 12288+96+7 = 12391
        // sec field stores seconds/2, so 7 = 14 seconds
        let ts = parse_fat_timestamp(12391, 22779);
        assert_eq!(ts, "7/27/2024 6:03:14");
    }

    #[test]
    fn test_scan_deleted_entry() {
        let mut entry = [0u8; 32];
        entry[0] = 0xE5; // deleted marker
        entry[1..8].copy_from_slice(b"ESTFILE"); // "?ESTFILE"
        entry[8..11].copy_from_slice(b"TXT");
        entry[11] = 0x20; // archive attribute
        entry[28..32].copy_from_slice(&100u32.to_le_bytes()); // size = 100

        let results = scan_deleted_entries(&entry, 0);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "?ESTFILE.TXT");
        assert_eq!(results[0].size, 100);
        assert!(!results[0].is_directory);
    }

    #[test]
    fn test_skip_lfn_entries() {
        let mut data = vec![0u8; 64];
        // LFN entry (attr = 0x0F)
        data[0] = 0xE5;
        data[11] = 0x0F;
        // Regular deleted entry
        data[32] = 0xE5;
        data[33..39].copy_from_slice(b"ELLOOO");
        data[40..43].copy_from_slice(b"TXT");
        data[43] = 0x20;

        let results = scan_deleted_entries(&data, 0);
        assert_eq!(results.len(), 1); // LFN skipped
    }

    #[test]
    fn test_end_of_directory() {
        let mut data = vec![0u8; 96];
        // Deleted entry
        data[0] = 0xE5;
        data[1..8].copy_from_slice(b"ESTFILE");
        data[8..11].copy_from_slice(b"TXT");
        data[11] = 0x20; // archive attribute
        // End marker at entry 2
        data[32] = 0x00;
        // Another deleted entry at entry 3 — should NOT be found
        data[64] = 0xE5;
        data[65..71].copy_from_slice(b"GNORED");
        data[72..75].copy_from_slice(b"TXT");
        data[75] = 0x20;

        let results = scan_deleted_entries(&data, 0);
        assert_eq!(results.len(), 1); // stopped at 0x00
    }
}
