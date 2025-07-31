
use std::fs::{self, File};
use std::io::{Write, Read};
use std::path::Path;
use zip::write::FileOptions;
use chrono::Utc;

pub fn export_all(output_path: &str) -> Result<(), &'static str> {
    let timestamp = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let full_path = format!("{output_path}_{timestamp}.zip");

    let file = File::create(&full_path).map_err(|_| "Failed to create export file")?;
    let mut zip = zip::ZipWriter::new(file);
    let options: FileOptions<()> = FileOptions::default().compression_method(zip::CompressionMethod::Stored);

    let targets = vec![
        ("data/vault.json", "vault.json"),
        ("data/canon", "canon/"),
        ("logs/audit_access_log.jsonl", "audit_access_log.jsonl"),
    ];

    for (src, dest) in targets {
        let path = Path::new(src);
        if path.is_file() {
            let mut buffer = Vec::new();
            File::open(path).and_then(|mut f| f.read_to_end(&mut buffer)).map_err(|_| "Read failed")?;
            zip.start_file(dest, options).map_err(|_| "Zip start failed")?;
            zip.write_all(&buffer).map_err(|_| "Zip write failed")?;
        } else if path.is_dir() {
            for entry in fs::read_dir(path).map_err(|_| "Read dir failed")? {
                let entry = entry.map_err(|_| "Entry fail")?;
                let file_path = entry.path();
                if file_path.is_file() {
                    let mut buffer = Vec::new();
                    File::open(&file_path).and_then(|mut f| f.read_to_end(&mut buffer)).map_err(|_| "Canon read fail")?;
                    let filename = file_path.file_name().unwrap().to_string_lossy();
                    zip.start_file(format!("canon/{filename}"), options).map_err(|_| "Canon zip fail")?;
                    zip.write_all(&buffer).map_err(|_| "Canon zip write fail")?;
                }
            }
        }
    }

    zip.finish().map_err(|_| "Zip finish fail")?;
    println!("[SigilExporter] Data exported to: {full_path}");
    Ok(())
}
