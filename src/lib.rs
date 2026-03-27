//! FATx — Pure Rust FAT12/16/32/exFAT filesystem parser for forensic analysis.
//!
//! Built on `fatfs` (FAT12/16/32) and `exfat-fs` (exFAT) crates with forensic
//! extensions: deleted file detection, volume metadata, and timeline generation.
//!
//! Accepts any `Read+Seek` source — works with raw images, E01 (via EwfReader),
//! VHD, or mounted drives.

pub mod volume;
pub mod exfat;
pub mod deleted;
pub mod timeline;

pub use volume::{FatVolume, FatEntry, FatType};
pub use exfat::ExfatVolume;

/// Detect filesystem type from boot sector bytes.
pub fn detect_fs_type(boot_sector: &[u8]) -> Option<&'static str> {
    if boot_sector.len() < 512 { return None; }

    // Check exFAT: "EXFAT   " at offset 3
    if boot_sector.len() >= 11 && &boot_sector[3..11] == b"EXFAT   " {
        return Some("exfat");
    }

    // Check NTFS: "NTFS    " at offset 3
    if boot_sector.len() >= 11 && &boot_sector[3..11] == b"NTFS    " {
        return Some("ntfs");
    }

    // Check FAT32: "FAT32   " at offset 82
    if boot_sector.len() >= 90 && &boot_sector[82..90] == b"FAT32   " {
        return Some("fat32");
    }

    // Check FAT16/12: "FAT" at offset 54
    if boot_sector.len() >= 62 && &boot_sector[54..57] == b"FAT" {
        let fat_str = std::str::from_utf8(&boot_sector[54..62]).unwrap_or("");
        if fat_str.starts_with("FAT16") { return Some("fat16"); }
        if fat_str.starts_with("FAT12") { return Some("fat12"); }
        return Some("fat");
    }

    None
}
