// Canon Validator - Canon-Compliant Refactor
// Purpose: Validate canon JSON files for schema conformity, entry integrity, and optional advisory fields with IRL-aware traceability

use std::fs;
use std::path::Path;
use chrono::Utc;
use serde::{Serialize, Deserialize};
use serde_json::{Value, json};
use crate::audit::{AuditEvent, LogLevel};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CanonValidationStatus {
    Valid,
    Warning,
    Error,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonValidationResult {
    pub entry_index: usize,
    pub entry_id: Option<String>,
    pub status: CanonValidationStatus,
    pub message: String,
    pub irl_score: f32,
    pub timestamp: chrono::DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonValidatorSummary {
    pub entry_count: usize,
    pub valid_count: usize,
    pub warning_count: usize,
    pub error_count: usize,
    pub audit: AuditEvent,
    pub results: Vec<CanonValidationResult>,
}

pub fn validate_canon_file(path: &Path) -> Result<CanonValidatorSummary, String> {
    let data = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read canon file: {}", e))?;

    let parsed: Value = serde_json::from_str(&data)
        .map_err(|e| format!("Invalid JSON: {}", e))?;

    let metadata = parsed.get("metadata")
        .ok_or("Missing 'metadata' block")?;
    let entries = parsed.get("entries")
        .ok_or("Missing 'entries' block")?;

    if metadata.get("edition").is_none() {
        return Err("Missing metadata.edition".into());
    }
    if metadata.get("schema_version").is_none() {
        return Err("Missing metadata.schema_version".into());
    }
    if metadata["schema_version"] != json!("v2.2") {
        return Err("Unsupported schema version (expected v2.2)".into());
    }

    let entries_arr = entries.as_array().ok_or("entries block is not an array")?;
    if entries_arr.is_empty() {
        return Err("entries array is empty".into());
    }

    let mut results = Vec::new();
    let mut valid_count = 0;
    let mut warning_count = 0;
    let mut error_count = 0;

    for (i, entry) in entries_arr.iter().enumerate() {
        let id = entry.get("id").and_then(|v| v.as_str()).map(|s| s.to_string());
        let now = Utc::now();

        if entry.get("id").is_none() || entry.get("name").is_none() || entry.get("type").is_none() {
            error_count += 1;
            results.push(CanonValidationResult {
                entry_index: i,
                entry_id: id.clone(),
                status: CanonValidationStatus::Error,
                message: "Missing required field(s): id, name, or type".into(),
                irl_score: 0.0,
                timestamp: now,
            });
            continue;
        }

        // Flavor field advisory
        let entry_type = entry.get("type").and_then(|t| t.as_str()).unwrap_or("");
        let has_desc = entry.get("description").is_some();
        let has_quote = entry.get("flavor_quote").is_some();

        let is_flavor_type = matches!(entry_type, "cyberware" | "bioware" | "spell" | "matrix" | "ritual" | "metamagic");

        if is_flavor_type && !(has_desc || has_quote) {
            warning_count += 1;
            results.push(CanonValidationResult {
                entry_index: i,
                entry_id: id.clone(),
                status: CanonValidationStatus::Warning,
                message: "Entry lacks flavor text or description".into(),
                irl_score: 0.75,
                timestamp: now,
            });
        } else {
            valid_count += 1;
            results.push(CanonValidationResult {
                entry_index: i,
                entry_id: id.clone(),
                status: CanonValidationStatus::Valid,
                message: "Entry is valid".into(),
                irl_score: 1.0,
                timestamp: now,
            });
        }
    }

    let audit = AuditEvent::new(
        "system",
        "canon_validator",
        "canon-validate-session",
        "canon_validator.rs"
    )
    .with_severity(LogLevel::Info)
    .with_context(format!("Validated {} entries in {:?}", results.len(), path));

    Ok(CanonValidatorSummary {
        entry_count: results.len(),
        valid_count,
        warning_count,
        error_count,
        audit,
        results,
    })
}