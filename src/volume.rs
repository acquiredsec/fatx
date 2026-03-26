//! FAT volume wrapper providing forensic-oriented read-only access.
//!
//! Wraps `fatfs::FileSystem` with a read-only I/O adapter.

use anyhow::Result;
use fatfs::{FileSystem, FsOptions, ReadWriteSeek, FileAttributes};
use serde::Serialize;
use std::io::{self, Read, Write, Seek, SeekFrom, Cursor};

/// Read-only wrapper: implements Read+Write+Seek but Write is a no-op.
/// This satisfies fatfs's ReadWriteSeek trait without ever modifying the source.
struct ReadOnlyWrapper<T: Read + Seek> {
    inner: T,
}

impl<T: Read + Seek> ReadOnlyWrapper<T> {
    fn new(inner: T) -> Self { Self { inner } }
}

impl<T: Read + Seek> Read for ReadOnlyWrapper<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> { self.inner.read(buf) }
}

impl<T: Read + Seek> Write for ReadOnlyWrapper<T> {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "Read-only forensic access"))
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

impl<T: Read + Seek> Seek for ReadOnlyWrapper<T> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> { self.inner.seek(pos) }
}

// ReadWriteSeek is auto-implemented for Read+Write+Seek

/// FAT filesystem type.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub enum FatType {
    Fat12,
    Fat16,
    Fat32,
    Unknown,
}

impl std::fmt::Display for FatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FatType::Fat12 => write!(f, "FAT12"),
            FatType::Fat16 => write!(f, "FAT16"),
            FatType::Fat32 => write!(f, "FAT32"),
            FatType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Volume metadata.
#[derive(Debug, Clone, Serialize)]
pub struct VolumeInfo {
    pub fat_type: FatType,
    pub label: String,
    pub volume_id: u32,
    pub cluster_size: u32,
    pub total_clusters: u32,
    pub free_clusters: u32,
    pub total_size: u64,
}

/// A file or directory entry with forensic metadata.
#[derive(Debug, Clone, Serialize)]
pub struct FatEntry {
    pub name: String,
    pub short_name: String,
    pub is_directory: bool,
    pub is_hidden: bool,
    pub is_system: bool,
    pub is_readonly: bool,
    pub size: u64,
    pub created: String,
    pub modified: String,
    pub accessed: String,
    pub full_path: String,
}

/// High-level FAT volume for forensic read-only access.
pub struct FatVolume<T: Read + Seek> {
    fs: FileSystem<ReadOnlyWrapper<T>>,
    pub info: VolumeInfo,
}

impl<T: Read + Seek> FatVolume<T> {
    /// Open a FAT volume from any Read+Seek source (read-only).
    pub fn open(source: T) -> Result<Self> {
        let wrapper = ReadOnlyWrapper::new(source);
        let opts = FsOptions::new().update_accessed_date(false);
        let fs = FileSystem::new(wrapper, opts)
            .map_err(|e| anyhow::anyhow!("Failed to open FAT filesystem: {e}"))?;

        let info = Self::read_volume_info(&fs);
        Ok(Self { fs, info })
    }

    fn read_volume_info(fs: &FileSystem<ReadOnlyWrapper<T>>) -> VolumeInfo {
        let fat_type = match fs.fat_type() {
            fatfs::FatType::Fat12 => FatType::Fat12,
            fatfs::FatType::Fat16 => FatType::Fat16,
            fatfs::FatType::Fat32 => FatType::Fat32,
        };

        let (cluster_size, total_clusters, free_clusters) = match fs.stats() {
            Ok(s) => (s.cluster_size(), s.total_clusters(), s.free_clusters()),
            Err(_) => (512, 0, 0),
        };

        VolumeInfo {
            fat_type,
            label: fs.volume_label(),
            volume_id: fs.volume_id(),
            cluster_size,
            total_clusters,
            free_clusters,
            total_size: total_clusters as u64 * cluster_size as u64,
        }
    }

    /// List entries in a directory.
    pub fn list_dir(&self, path: &str) -> Result<Vec<FatEntry>> {
        let dir = if path == "/" || path.is_empty() {
            self.fs.root_dir()
        } else {
            let clean = path.trim_start_matches('/').replace('/', "\\");
            self.fs.root_dir().open_dir(&clean)
                .map_err(|e| anyhow::anyhow!("Failed to open '{}': {e}", path))?
        };

        let mut entries = Vec::new();
        for entry_result in dir.iter() {
            let entry = match entry_result {
                Ok(e) => e,
                Err(_) => continue,
            };

            let name = entry.file_name();
            if name == "." || name == ".." { continue; }

            let parent = if path == "/" || path.is_empty() { "" } else { path.trim_end_matches('/') };
            let full_path = if parent.is_empty() { format!("/{}", name) } else { format!("{}/{}", parent, name) };

            entries.push(FatEntry {
                name,
                short_name: entry.short_file_name(),
                is_directory: entry.is_dir(),
                is_hidden: entry.attributes().contains(FileAttributes::HIDDEN),
                is_system: entry.attributes().contains(FileAttributes::SYSTEM),
                is_readonly: entry.attributes().contains(FileAttributes::READ_ONLY),
                size: entry.len(),
                created: format_fat_datetime(entry.created()),
                modified: format_fat_datetime(entry.modified()),
                accessed: format_fat_date(entry.accessed()),
                full_path,
            });
        }
        Ok(entries)
    }

    /// Recursively list all entries.
    pub fn list_all(&self) -> Result<Vec<FatEntry>> {
        let mut all = Vec::new();
        self.list_recursive("/", &mut all)?;
        Ok(all)
    }

    fn list_recursive(&self, path: &str, out: &mut Vec<FatEntry>) -> Result<()> {
        let entries = self.list_dir(path)?;
        for entry in &entries {
            out.push(entry.clone());
            if entry.is_directory {
                self.list_recursive(&entry.full_path, out)?;
            }
        }
        Ok(())
    }

    /// Read file content.
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        let clean = path.trim_start_matches('/').replace('/', "\\");
        let mut file = self.fs.root_dir().open_file(&clean)
            .map_err(|e| anyhow::anyhow!("Failed to open file '{}': {e}", path))?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Ok(data)
    }

    /// Extract a file to disk.
    pub fn extract_file(&self, src_path: &str, dest_path: &std::path::Path) -> Result<u64> {
        let data = self.read_file(src_path)?;
        std::fs::write(dest_path, &data)?;
        Ok(data.len() as u64)
    }
}

fn format_fat_datetime(dt: fatfs::DateTime) -> String {
    format!("{}/{}/{} {}:{:02}:{:02}",
        dt.date.month, dt.date.day, dt.date.year,
        dt.time.hour, dt.time.min, dt.time.sec)
}

fn format_fat_date(d: fatfs::Date) -> String {
    format!("{}/{}/{}", d.month, d.day, d.year)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_fat_image() -> Vec<u8> {
        let size = 1024 * 1024;
        let mut data = vec![0u8; size];

        // Format with fatfs (needs Read+Write+Seek)
        {
            let cursor = Cursor::new(&mut data[..]);
            fatfs::format_volume(cursor, fatfs::FormatVolumeOptions::new()
                .volume_label(*b"TESTVOLUME "))
                .expect("Format failed");
        }

        // Write test files (needs write access)
        {
            let cursor = Cursor::new(&mut data[..]);
            let fs = FileSystem::new(cursor, FsOptions::new()).unwrap();
            let root = fs.root_dir();
            let mut f = root.create_file("test.txt").unwrap();
            f.write_all(b"Hello from FATx!").unwrap();
            f.flush().unwrap();

            let sub = root.create_dir("docs").unwrap();
            let mut f2 = sub.create_file("readme.md").unwrap();
            f2.write_all(b"# FATx Test").unwrap();
            f2.flush().unwrap();
        }

        data
    }

    #[test]
    fn test_open_volume() {
        let data = create_test_fat_image();
        let vol = FatVolume::open(Cursor::new(data)).unwrap();
        assert_eq!(vol.info.fat_type, FatType::Fat12);
        assert!(vol.info.label.contains("TESTVOLUME"));
    }

    #[test]
    fn test_list_root() {
        let data = create_test_fat_image();
        let vol = FatVolume::open(Cursor::new(data)).unwrap();
        let entries = vol.list_dir("/").unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"test.txt"));
        assert!(names.contains(&"docs"));
    }

    #[test]
    fn test_read_file() {
        let data = create_test_fat_image();
        let vol = FatVolume::open(Cursor::new(data)).unwrap();
        let content = vol.read_file("/test.txt").unwrap();
        assert_eq!(content, b"Hello from FATx!");
    }

    #[test]
    fn test_list_all() {
        let data = create_test_fat_image();
        let vol = FatVolume::open(Cursor::new(data)).unwrap();
        let all = vol.list_all().unwrap();
        assert!(all.len() >= 3);
    }

    #[test]
    fn test_extract_file() {
        let data = create_test_fat_image();
        let vol = FatVolume::open(Cursor::new(data)).unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let bytes = vol.extract_file("/test.txt", tmp.path()).unwrap();
        assert_eq!(bytes, 16);
        assert_eq!(std::fs::read(tmp.path()).unwrap(), b"Hello from FATx!");
    }
}
