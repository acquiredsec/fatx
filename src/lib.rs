//! FATx — Pure Rust FAT12/16/32 filesystem parser for forensic analysis.
//!
//! Built on top of the `fatfs` crate for core FAT parsing, with forensic
//! extensions: deleted file detection, volume metadata extraction, and
//! timeline generation.
//!
//! Accepts any `Read+Seek` source — works with raw images, E01 (via EwfReader),
//! VHD, or mounted drives.

pub mod volume;
pub mod deleted;
pub mod timeline;

pub use volume::{FatVolume, FatEntry, FatType};
