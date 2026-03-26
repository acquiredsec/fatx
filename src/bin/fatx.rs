//! FATx CLI — forensic FAT filesystem analysis tool.

use clap::{Parser, Subcommand};
use fatx::{FatVolume, FatEntry};
use std::io::Cursor;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "fatx", version, about = "FATx: Forensic FAT12/16/32 filesystem parser")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show volume information (FAT type, label, size, cluster info)
    Info {
        /// Path to FAT image file
        image: PathBuf,
        /// Partition offset in bytes (for full-disk images)
        #[arg(long, default_value = "0")]
        offset: u64,
    },

    /// Show directory tree
    Tree {
        /// Path to FAT image file
        image: PathBuf,
        #[arg(long, default_value = "0")]
        offset: u64,
        /// Maximum depth to display
        #[arg(short = 'd', long, default_value = "3")]
        max_depth: usize,
    },

    /// List directory contents with timestamps and attributes
    List {
        /// Path to FAT image file
        image: PathBuf,
        /// Directory path within the volume (default: root)
        #[arg(short, long, default_value = "/")]
        path: String,
        #[arg(long, default_value = "0")]
        offset: u64,
        /// Recursive listing
        #[arg(short, long)]
        recursive: bool,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Extract a file from the image
    Extract {
        /// Path to FAT image file
        image: PathBuf,
        /// File path within the volume
        file_path: String,
        /// Output path
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long, default_value = "0")]
        offset: u64,
    },

    /// Generate a CSV timeline of all file timestamps
    Timeline {
        /// Path to FAT image file
        image: PathBuf,
        #[arg(long, default_value = "0")]
        offset: u64,
        /// Output CSV file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Scan for deleted files
    Deleted {
        /// Path to FAT image file
        image: PathBuf,
        #[arg(long, default_value = "0")]
        offset: u64,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Info { image, offset } => cmd_info(image, offset),
        Commands::Tree { image, offset, max_depth } => cmd_tree(image, offset, max_depth),
        Commands::List { image, path, offset, recursive, json } => cmd_list(image, path, offset, recursive, json),
        Commands::Extract { image, file_path, output, offset } => cmd_extract(image, file_path, output, offset),
        Commands::Timeline { image, offset, output } => cmd_timeline(image, offset, output),
        Commands::Deleted { image, offset, json } => cmd_deleted(image, offset, json),
    };

    if let Err(e) = result {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}

fn open_volume(image: PathBuf, offset: u64) -> anyhow::Result<FatVolume<std::io::BufReader<std::fs::File>>> {
    let mut file = std::fs::File::open(&image)?;
    if offset > 0 {
        use std::io::Seek;
        file.seek(std::io::SeekFrom::Start(offset))?;
    }
    let reader = std::io::BufReader::new(file);
    FatVolume::open(reader)
}

fn cmd_info(image: PathBuf, offset: u64) -> anyhow::Result<()> {
    let vol = open_volume(image, offset)?;
    let info = &vol.info;
    println!("FAT Type:           {}", info.fat_type);
    println!("Volume Label:       {}", if info.label.is_empty() { "(none)" } else { &info.label });
    println!("Cluster Size:       {} bytes", info.cluster_size);
    println!("Total Clusters:     {}", info.total_clusters);
    println!("Free Clusters:      {}", info.free_clusters);
    println!("Total Size:         {:.1} MB ({} bytes)", info.total_size as f64 / (1024.0 * 1024.0), info.total_size);
    println!("Volume ID:          0x{:08X}", info.volume_id);
    Ok(())
}

fn cmd_tree(image: PathBuf, offset: u64, max_depth: usize) -> anyhow::Result<()> {
    let vol = open_volume(image, offset)?;
    print_tree(&vol, "/", 0, max_depth)?;
    Ok(())
}

fn print_tree<T: std::io::Read + std::io::Seek>(
    vol: &FatVolume<T>, path: &str, depth: usize, max_depth: usize
) -> anyhow::Result<()> {
    if depth > max_depth { return Ok(()); }
    let entries = vol.list_dir(path)?;
    for (i, entry) in entries.iter().enumerate() {
        let is_last = i == entries.len() - 1;
        let prefix = if depth == 0 { String::new() } else {
            "  ".repeat(depth - 1) + if is_last { "└── " } else { "├── " }
        };
        let icon = if entry.is_directory { "📁" } else { "📄" };
        let size = if entry.is_directory { String::new() } else { format!(" ({})", format_size(entry.size)) };
        println!("{}{} {}{}", prefix, icon, entry.name, size);
        if entry.is_directory {
            print_tree(vol, &entry.full_path, depth + 1, max_depth)?;
        }
    }
    Ok(())
}

fn cmd_list(image: PathBuf, path: String, offset: u64, recursive: bool, json: bool) -> anyhow::Result<()> {
    let vol = open_volume(image, offset)?;
    let entries = if recursive { vol.list_all()? } else { vol.list_dir(&path)? };

    if json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(());
    }

    println!("{:<40} {:>10} {:<20} {:<20} {}", "Name", "Size", "Modified", "Created", "Path");
    println!("{}", "-".repeat(110));
    for entry in &entries {
        let type_str = if entry.is_directory { "DIR" } else { "" };
        let size_str = if entry.is_directory { String::new() } else { format_size(entry.size) };
        println!("{:<40} {:>10} {:<20} {:<20} {}",
            entry.name, size_str, entry.modified, entry.created, entry.full_path);
    }
    println!("\n{} entries", entries.len());
    Ok(())
}

fn cmd_extract(image: PathBuf, file_path: String, output: PathBuf, offset: u64) -> anyhow::Result<()> {
    let vol = open_volume(image, offset)?;
    let bytes = vol.extract_file(&file_path, &output)?;
    println!("Extracted {} ({} bytes) to {}", file_path, bytes, output.display());
    Ok(())
}

fn cmd_timeline(image: PathBuf, offset: u64, output: Option<PathBuf>) -> anyhow::Result<()> {
    let vol = open_volume(image, offset)?;
    let entries = vol.list_all()?;

    if let Some(path) = output {
        let mut file = std::fs::File::create(&path)?;
        fatx::timeline::write_timeline_csv(&entries, &mut file)?;
        println!("Timeline written to {} ({} entries)", path.display(), entries.len());
    } else {
        fatx::timeline::write_timeline_csv(&entries, &mut std::io::stdout())?;
    }
    Ok(())
}

fn cmd_deleted(image: PathBuf, offset: u64, json: bool) -> anyhow::Result<()> {
    // For deleted file scanning, we need to read raw directory data
    // For now, show a message — full implementation requires reading raw clusters
    println!("Scanning for deleted files...");

    // Read raw image and scan for 0xE5 entries in directory clusters
    let data = std::fs::read(&image)?;
    let start = offset as usize;
    let scan_data = &data[start..];

    // Simple heuristic: scan the first few MB for deleted entries
    let scan_limit = scan_data.len().min(10 * 1024 * 1024);
    let entries = fatx::deleted::scan_deleted_entries(&scan_data[..scan_limit], offset);

    if json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(());
    }

    if entries.is_empty() {
        println!("No deleted files found.");
        return Ok(());
    }

    println!("{:<30} {:>10} {:>12} {:<20} {}", "Name", "Size", "Cluster", "Modified", "Offset");
    println!("{}", "-".repeat(90));
    for entry in &entries {
        println!("{:<30} {:>10} {:>12} {:<20} 0x{:X}",
            entry.name, entry.size, entry.first_cluster, entry.modified, entry.offset);
    }
    println!("\n{} deleted entries found", entries.len());
    Ok(())
}

fn format_size(bytes: u64) -> String {
    if bytes == 0 { return String::new(); }
    if bytes < 1024 { return format!("{} B", bytes); }
    if bytes < 1024 * 1024 { return format!("{:.1} KB", bytes as f64 / 1024.0); }
    if bytes < 1024 * 1024 * 1024 { return format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0)); }
    format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
}
