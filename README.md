# FATx

FATx is a pure-Rust library and command-line tool for read-only forensic
inspection of FAT12, FAT16, FAT32, and exFAT filesystems. It can identify a
volume, enumerate directories, extract a selected file, produce a CSV
timeline, and perform a bounded heuristic scan for deleted directory entries.

## Features

- FAT12/16/32 and exFAT volume access.
- Full-volume or partition-at-offset operation.
- Volume geometry, label, allocation, and identifier reporting.
- Tree and directory listings with timestamps and attributes.
- JSON output for directory and deleted-entry listings.
- File extraction from a filesystem path to an operator-selected destination.
- CSV filesystem timeline generation.
- Reusable `fatx` Rust library for other forensic applications.

FATx never intentionally writes to the source image. Extraction and timeline
commands write only to paths supplied by the operator.

## Build and test

```bash
cargo build --release
cargo test --all-features
```

The CLI is produced at `target/release/fatx` (`fatx.exe` on Windows).

## Commands

### Inspect volume metadata

```bash
fatx info evidence.img
fatx info disk.dd --offset 1048576
```

`info` reports the detected FAT type, volume label and ID, cluster size, total
and free clusters, and calculated filesystem size.

### Display a directory tree

```bash
fatx tree evidence.img
fatx tree evidence.img --max-depth 8
```

The default maximum depth is three. Use a bounded depth on large or damaged
volumes to avoid excessive traversal.

### List directory entries

```bash
fatx list evidence.img --path /DCIM
fatx list evidence.img --path / --recursive --json
```

Text output includes name, size, modified time, created time, and full path.
JSON output serializes the complete entry records exposed by the library.

### Extract one file

```bash
fatx extract evidence.img /DCIM/100MEDIA/IMG0001.JPG \
  --output ./exports/IMG0001.JPG
```

The output path names a file, not a directory. Hash the exported file and
record both its filesystem path and destination in the case notes.

### Generate a timeline

```bash
fatx timeline evidence.img --output fat_timeline.csv
fatx timeline evidence.img > fat_timeline.csv
```

The command recursively enumerates the filesystem and writes the available
FAT timestamps and entry metadata as CSV. FAT timestamps have filesystem- and
implementation-specific precision and timezone limitations; they must not be
interpreted as equivalent to NTFS timestamps.

### Scan deleted entries

```bash
fatx deleted evidence.img
fatx deleted evidence.img --json
```

The current implementation performs a heuristic scan for directory entries
whose first byte is `0xE5`. It scans at most the first 10 MiB beginning at the
selected offset. This is triage, not exhaustive recovery: a negative result
does not establish that deleted entries are absent, and reported candidates
require validation against directory structure and cluster allocation.

## Partition offsets

Every command accepts `--offset <BYTES>`, defaulting to zero. For a full-disk
image, provide the byte offset of the FAT partition:

```text
byte offset = starting logical block address × logical sector size
```

Confirm the sector size and partition start with a trusted partition-table
tool before analysis. Supplying a sector count where bytes are expected will
address the wrong location.

## Library usage

The package also exposes `FatVolume` and related entry/timeline types:

```rust
use fatx::FatVolume;
use std::{fs::File, io::BufReader};

let image = BufReader::new(File::open("evidence.img")?);
let volume = FatVolume::open(image)?;
for entry in volume.list_dir("/")? {
    println!("{} {}", entry.full_path, entry.size);
}
# Ok::<(), anyhow::Error>(())
```

Callers are responsible for positioning a reader at the intended partition
when the filesystem does not begin at byte zero.

## Forensic workflow

1. Work from a verified image or authorized read-only duplicate.
2. Record the source hash, FATx commit/version, partition offset, command line,
   and analysis-host timezone.
3. Run `info` before traversal and preserve its output with the case notes.
4. Write extracted files and timelines to a separate case-output location.
5. Hash exports and retain their original filesystem paths.
6. Validate significant timestamps, deleted candidates, and allocation state
   with a second trusted method.

Malformed filesystems can contain cycles, invalid cluster chains, or hostile
metadata. Analyze untrusted images on an isolated workstation and retain tool
errors or warnings with the result set.

## Current limitations

- The CLI does not parse a disk partition table; the operator supplies the
  partition byte offset.
- Deleted-entry scanning is bounded and heuristic.
- The CLI extracts individual files, not an entire tree.
- FAT timestamp semantics and available fields vary by filesystem variant.
- This tool does not acquire media or bypass encryption.

## Development checks

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release
git diff --check
```

Use synthetic, redistributable filesystem fixtures. Never commit case images,
recovered personal data, credentials, or proprietary evidence.

## License

MIT. See the package metadata for repository and authorship information.
