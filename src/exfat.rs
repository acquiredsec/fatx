//! exFAT volume wrapper providing forensic-oriented read-only access.

use anyhow::Result;
use exfat_fs::dir::Root;
use exfat_fs::dir::entry::fs::FsElement;
use exfat_fs::disk::ReadOffset;
use exfat_fs::timestamp::Timestamp;
use serde::Serialize;
use std::io::{Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex};

use crate::volume::FatEntry;

/// Adapter: wraps Read+Seek into exfat-fs's ReadOffset trait.
#[derive(Debug)]
pub struct ReadSeekAdapter<T: Read + Seek> {
    inner: Mutex<T>,
}

impl<T: Read + Seek> ReadSeekAdapter<T> {
    pub fn new(inner: T) -> Self { Self { inner: Mutex::new(inner) } }
}

#[derive(Debug)]
pub struct AdapterError(std::io::Error);
impl std::fmt::Display for AdapterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.0) }
}
impl From<AdapterError> for std::io::Error {
    fn from(e: AdapterError) -> Self { e.0 }
}

impl exfat_fs::disk::PartitionError for AdapterError {
    fn unexpected_eop() -> Self { AdapterError(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "unexpected end of partition")) }
    fn cluster_not_found(cluster: u32) -> Self { AdapterError(std::io::Error::new(std::io::ErrorKind::NotFound, format!("cluster {} not found", cluster))) }
}

impl<T: Read + Seek> ReadOffset for ReadSeekAdapter<T> {
    type Err = AdapterError;
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::result::Result<usize, Self::Err> {
        let mut inner = self.inner.lock().unwrap();
        inner.seek(SeekFrom::Start(offset)).map_err(AdapterError)?;
        inner.read(buf).map_err(AdapterError)
    }
}

/// exFAT volume info.
#[derive(Debug, Clone, Serialize)]
pub struct ExfatVolumeInfo {
    pub label: String,
}

/// High-level exFAT volume for forensic read-only access.
pub struct ExfatVolume<T: Read + Seek + std::fmt::Debug> {
    adapter: Arc<ReadSeekAdapter<T>>,
    pub info: ExfatVolumeInfo,
}

impl<T: Read + Seek + std::fmt::Debug> ExfatVolume<T> {
    pub fn open(source: T) -> Result<Self> {
        let adapter = Arc::new(ReadSeekAdapter::new(source));
        let root = Root::open(adapter.clone())
            .map_err(|e| anyhow::anyhow!("Failed to open exFAT: {:?}", e))?;
        let label = root.label().map(|l| format!("{:?}", l)).unwrap_or_default();
        Ok(Self { adapter, info: ExfatVolumeInfo { label } })
    }

    /// List entries in root directory.
    pub fn list_root(&self) -> Result<Vec<FatEntry>> {
        let mut root = Root::open(self.adapter.clone())
            .map_err(|e| anyhow::anyhow!("Failed to open exFAT root: {:?}", e))?;
        Ok(items_to_entries(root.items(), "/"))
    }

    /// List entries in a directory by navigating from root.
    pub fn list_dir(&self, path: &str) -> Result<Vec<FatEntry>> {
        if path == "/" || path.is_empty() {
            return self.list_root();
        }

        let mut root = Root::open(self.adapter.clone())
            .map_err(|e| anyhow::anyhow!("Failed to open exFAT root: {:?}", e))?;

        let parts: Vec<&str> = path.trim_start_matches('/').split('/').filter(|s| !s.is_empty()).collect();

        // Navigate down from root to target directory
        let items = navigate_to_dir(root.items(), &parts, 0)?;
        Ok(items_to_entries(&items, path))
    }

    /// Recursively list all entries.
    pub fn list_all(&self) -> Result<Vec<FatEntry>> {
        let mut all = Vec::new();
        self.list_recursive("/", &mut all)?;
        Ok(all)
    }

    fn list_recursive(&self, path: &str, out: &mut Vec<FatEntry>) -> Result<()> {
        let entries = match self.list_dir(path) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("Warning: skipping unreadable directory '{}': {}", path, e);
                return Ok(()); // skip unreadable directories
            }
        };
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
        let mut root = Root::open(self.adapter.clone())
            .map_err(|e| anyhow::anyhow!("Failed to open exFAT: {:?}", e))?;

        let parts: Vec<&str> = path.trim_start_matches('/').split('/').filter(|s| !s.is_empty()).collect();
        if parts.is_empty() { anyhow::bail!("Invalid file path"); }

        read_file_from_items(root.items(), &parts, 0)
    }

    /// Extract a file to disk.
    pub fn extract_file(&self, src_path: &str, dest_path: &std::path::Path) -> Result<u64> {
        let data = self.read_file(src_path)?;
        std::fs::write(dest_path, &data)?;
        Ok(data.len() as u64)
    }
}

/// Navigate into nested directories and return the target dir's children.
fn navigate_to_dir<O: ReadOffset + std::fmt::Debug>(
    items: &mut [FsElement<O>],
    parts: &[&str],
    depth: usize,
) -> Result<Vec<FsElement<O>>> {
    if depth >= parts.len() {
        // We're at the target — but we can't return borrowed items.
        // This is a limitation. For now, bail.
        anyhow::bail!("Cannot navigate: exfat-fs doesn't support cloning items");
    }

    let target = parts[depth];
    for item in items.iter_mut() {
        if let FsElement::D(ref dir) = item {
            if dir.name() == target {
                let children = match dir.open() {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("Warning: cannot open dir '{}': {:?}", target, e);
                        return Ok(Vec::new());
                    }
                };
                if depth + 1 >= parts.len() {
                    return Ok(children);
                } else {
                    // Need to navigate deeper — but children is owned Vec
                    let mut children = children;
                    return navigate_to_dir(&mut children, parts, depth + 1);
                }
            }
        }
    }

    anyhow::bail!("Directory '{}' not found", target)
}

/// Read a file by navigating the directory tree.
fn read_file_from_items<O: ReadOffset + std::fmt::Debug>(
    items: &mut [FsElement<O>],
    parts: &[&str],
    depth: usize,
) -> Result<Vec<u8>> where O::Err: Into<std::io::Error> {
    if parts.is_empty() { anyhow::bail!("Empty path"); }

    let target = parts[depth];
    let is_last = depth == parts.len() - 1;

    for item in items.iter_mut() {
        match item {
            FsElement::F(ref mut file) if is_last && file.name() == target => {
                let mut data = Vec::new();
                file.read_to_end(&mut data)?;
                return Ok(data);
            }
            FsElement::D(ref dir) if !is_last && dir.name() == target => {
                let mut children = dir.open()
                    .map_err(|e| anyhow::anyhow!("Dir error: {:?}", e))?;
                return read_file_from_items(&mut children, parts, depth + 1);
            }
            _ => {}
        }
    }

    anyhow::bail!("Not found: {}", target)
}

fn items_to_entries<O: ReadOffset + std::fmt::Debug>(items: &[FsElement<O>], parent_path: &str) -> Vec<FatEntry> {
    let mut entries = Vec::new();
    for item in items {
        match item {
            FsElement::D(dir) => {
                let name = dir.name().to_string();
                let full_path = if parent_path == "/" { format!("/{}", name) } else { format!("{}/{}", parent_path, name) };
                let ts = dir.timestamps();
                entries.push(FatEntry {
                    name, short_name: String::new(), is_directory: true,
                    is_hidden: false, is_system: false, is_readonly: false, size: 0,
                    created: format_ts(ts.created()), modified: format_ts(ts.modified()), accessed: format_ts(ts.accessed()),
                    full_path,
                });
            }
            FsElement::F(file) => {
                let name = file.name().to_string();
                let full_path = if parent_path == "/" { format!("/{}", name) } else { format!("{}/{}", parent_path, name) };
                let ts = file.timestamps();
                entries.push(FatEntry {
                    name, short_name: String::new(), is_directory: false,
                    is_hidden: false, is_system: false, is_readonly: false, size: file.len(),
                    created: format_ts(ts.created()), modified: format_ts(ts.modified()), accessed: format_ts(ts.accessed()),
                    full_path,
                });
            }
        }
    }
    entries
}

fn format_ts(ts: &Timestamp) -> String {
    let d = ts.date();
    let t = ts.time();
    format!("{}/{}/{} {}:{:02}:{:02}", d.month, d.day, d.year, t.hour, t.minute, t.second)
}
