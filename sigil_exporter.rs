// Canon-Compliant sigil_exporter.rs
// Purpose: Export runtime data (canon, vault, audit logs) with audit trace and version-safe structure

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use zip::write::FileOptions;
use chrono::Utc;

use crate::audit::{AuditEvent, LogLevel};

#[derive(Debug)]
pub struct ExportResult {
    pub success: bool,
    pub archive_path: String,
    pub audit: AuditEvent,
    pub message: String,
}

pub fn export_all(output_path: &str) -> Result<ExportResult, String> {
    let timestamp = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let full_path = format!("{}_{}.zip", output_path, timestamp);

    let file = File::create(&full_path)
        .map_err(|e| format!("Failed to create export file: {}", e))?;

    let mut zip = zip::ZipWriter::new(file);
    let options = FileOptions::default().compression_method(zip::CompressionMethod::Stored);

    let targets = vec![
        ("data/vault.json", "vault.json"),
        ("data/canon", "canon/"),
        ("data/audit.log", "audit.log"),
    ];

    for (src, dst) in targets {
        let path = Path::new(src);
        if path.is_file() {
            let mut buffer = Vec::new();
            File::open(path)
                .and_then(|mut f| f.read_to_end(&mut buffer))
                .map_err(|e| format!("Failed to read file {}: {}", src, e))?;

            zip.start_file(dst, options)
                .map_err(|e| format!("ZIP error for file {}: {}", dst, e))?;

            zip.write_all(&buffer)
                .map_err(|e| format!("Failed to write {} into zip: {}", dst, e))?;
        } else if path.is_dir() {
            zip.add_directory(dst, options)
                .map_err(|e| format!("Failed to add directory {}: {}", dst, e))?;

            for entry in fs::read_dir(path).map_err(|e| format!("Read dir error: {}", e))? {
                let entry = entry.map_err(|e| format!("Dir entry error: {}", e))?;
                let entry_path = entry.path();
                if entry_path.is_file() {
                    let file_name = entry_path.file_name()
                        .ok_or_else(|| format!("Invalid filename in {:?}", entry_path))?
                        .to_string_lossy();

                    let mut buffer = Vec::new();
                    File::open(&entry_path)
                        .and_then(|mut f| f.read_to_end(&mut buffer))
                        .map_err(|e| format!("Read failed for {:?}: {}", entry_path, e))?;

                    let zip_path = format!("{}{}", dst, file_name);
                    zip.start_file(&zip_path, options)
                        .map_err(|e| format!("ZIP error for {}: {}", zip_path, e))?;
                    zip.write_all(&buffer)
                        .map_err(|e| format!("Write error for {}: {}", zip_path, e))?;
                }
            }
        }
    }

    zip.finish().map_err(|e| format!("Failed to finalize zip: {}", e))?;

    let audit_event = AuditEvent::export_event("runtime_export", LogLevel::Info, &full_path);
    audit_event.emit();

    Ok(ExportResult {
        success: true,
        archive_path: full_path,
        audit: audit_event,
        message: "Export successful".to_string(),
    })
}
