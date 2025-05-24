// Canon-Compliant sealtool.rs
// Purpose: Cryptographically seal TrustedKnowledgeEntry with audit and provenance

use sha2::{Sha256, Digest};
use chrono::{Utc, DateTime};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use crate::trusted_knowledge::TrustedKnowledgeEntry;
use crate::audit::{AuditEvent, LogLevel};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SealedCanonEntry {
    pub entry: TrustedKnowledgeEntry,
    pub sha256: String,
    pub sealed_by: String,
    pub sealed_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct SealResult {
    pub success: bool,
    pub message: String,
    pub audit: AuditEvent,
    pub hash: String,
}

pub fn seal_file(
    path: &str,
    out_path: &str,
    signer_id: &str
) -> Result<SealResult, String> {
    let mut file = File::open(path).map_err(|e| format!("Cannot open canon file: {}", e))?;
    let mut content = String::new();
    file.read_to_string(&mut content).map_err(|e| format!("Read error: {}", e))?;

    let entry: TrustedKnowledgeEntry = serde_json::from_str(&content)
        .map_err(|e| format!("Parse error: {}", e))?;

    let hash_bytes = Sha256::digest(content.as_bytes());
    let hash_hex = format!("{:x}", hash_bytes);

    let sealed = SealedCanonEntry {
        entry,
        sha256: hash_hex.clone(),
        sealed_by: signer_id.into(),
        sealed_at: Utc::now(),
    };

    let audit = AuditEvent::new(
        signer_id,
        "seal_canon_entry",
        &sealed.sha256,
        "sealtool.rs"
    )
    .with_severity(LogLevel::Info)
    .with_context(format!(
        "Sealed canon entry from '{}', output to '{}'",
        path, out_path
    ));

    let out_json = serde_json::to_string_pretty(&sealed)
        .map_err(|e| format!("Serialization error: {}", e))?;

    fs::write(out_path, out_json).map_err(|e| format!("Write failed: {}", e))?;

    Ok(SealResult {
        success: true,
        message: "Canon entry sealed successfully".into(),
        audit,
        hash: hash_hex,
    })
}
