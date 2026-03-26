//! Timeline generation from FAT filesystem entries.
//!
//! Produces CSV-formatted timelines compatible with forensic analysis tools.

use crate::volume::FatEntry;
use std::io::Write;

/// Generate a CSV timeline from a list of FAT entries.
pub fn write_timeline_csv<W: Write>(entries: &[FatEntry], out: &mut W) -> anyhow::Result<()> {
    writeln!(out, "Timestamp,Type,Path,Size,Attributes")?;

    for entry in entries {
        let attrs = build_attr_string(entry);

        // Modified timestamp
        if !entry.modified.is_empty() {
            writeln!(out, "{},Modified,\"{}\",{},{}", entry.modified, entry.full_path, entry.size, attrs)?;
        }
        // Created timestamp
        if !entry.created.is_empty() {
            writeln!(out, "{},Created,\"{}\",{},{}", entry.created, entry.full_path, entry.size, attrs)?;
        }
        // Accessed timestamp
        if !entry.accessed.is_empty() {
            writeln!(out, "{},Accessed,\"{}\",{},{}", entry.accessed, entry.full_path, entry.size, attrs)?;
        }
    }
    Ok(())
}

fn build_attr_string(entry: &FatEntry) -> String {
    let mut parts = Vec::new();
    if entry.is_directory { parts.push("DIR"); }
    if entry.is_hidden { parts.push("H"); }
    if entry.is_system { parts.push("S"); }
    if entry.is_readonly { parts.push("R"); }
    parts.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timeline_csv() {
        let entries = vec![FatEntry {
            name: "test.txt".into(),
            short_name: "TEST~1.TXT".into(),
            is_directory: false,
            is_hidden: false,
            is_system: false,
            is_readonly: false,
            size: 1024,
            created: "1/15/2024 10:30:00".into(),
            modified: "1/16/2024 11:00:00".into(),
            accessed: "1/16/2024".into(),
            full_path: "/test.txt".into(),
        }];

        let mut buf = Vec::new();
        write_timeline_csv(&entries, &mut buf).unwrap();
        let csv = String::from_utf8(buf).unwrap();

        assert!(csv.contains("Timestamp,Type,Path,Size,Attributes"));
        assert!(csv.contains("1/16/2024 11:00:00,Modified,\"/test.txt\",1024,"));
        assert!(csv.contains("1/15/2024 10:30:00,Created,\"/test.txt\",1024,"));
    }
}
