// canon_validator.rs - Validates canon JSON against MMF Canon Schema v2.2 with optional flavor fields

use std::fs;
use std::path::Path;
use serde_json::{Value, json};
use sha2::{Sha256, Digest};

pub fn validate_canon_file(path: &Path) -> Result<(), String> {
    let data = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read canon file: {}", e))?;

    let parsed: Value = serde_json::from_str(&data)
        .map_err(|e| format!("Invalid JSON: {}", e))?;

    let metadata = parsed.get("metadata")
        .ok_or("Missing 'metadata' block")?;

    let entries = parsed.get("entries")
        .ok_or("Missing 'entries' block")?;

    if !metadata.get("edition").is_some() { return Err("Missing metadata.edition".into()); }
    if !metadata.get("schema_version").is_some() { return Err("Missing metadata.schema_version".into()); }
    if metadata["schema_version"] != json!("v2.2") {
        return Err("Unsupported schema version (expected v2.2)".into());
    }

    let entries_arr = entries.as_array().ok_or("entries block is not an array")?;
    if entries_arr.is_empty() {
        return Err("entries array is empty".into());
    }

    for (i, entry) in entries_arr.iter().enumerate() {
        if !entry.get("id").is_some() {
            return Err(format!("Entry [{}] missing 'id' field", i));
        }
        if !entry.get("name").is_some() {
            return Err(format!("Entry [{}] missing 'name' field", i));
        }
        if !entry.get("type").is_some() {
            return Err(format!("Entry [{}] missing 'type' field", i));
        }

        // Flavor warnings (non-fatal)
        let entry_type = entry.get("type").and_then(|t| t.as_str()).unwrap_or("");
        let has_desc = entry.get("description").is_some();
        let has_quote = entry.get("flavor_quote").is_some();

        if matches!(entry_type, "cyberware" | "bioware" | "spell" | "matrix" | "ritual" | "metamagic") {
            if !has_desc {
                println!("WARNING: Entry [{}] '{}' lacks a description.", i, entry.get("name").unwrap_or(&json!("(unknown)")));
            }
            if !has_quote {
                println!("WARNING: Entry [{}] '{}' lacks a flavor quote.", i, entry.get("name").unwrap_or(&json!("(unknown)")));
            }
        }
    }

    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let hash = format!("{:x}", hasher.finalize());

    println!("Canon schema validated. Entries: {}, SHA256: {}", entries_arr.len(), hash);
    Ok(())
}
