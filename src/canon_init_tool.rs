// Phase 1 - Canon Extension: canon_init_tool.rs
// Purpose: Canon-safe initialization of trusted entries with structured logging and audit integrity

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::Utc;
use serde::{Serialize, Deserialize};
use serde_json;

use crate::canon_store_sled::CanonStoreSled;
use crate::config_loader::load_config;
use crate::license_validator::validate_license;
use crate::session_context::SessionContext;
use crate::trusted_knowledge::{TrustedKnowledgeEntry, SigilVerdict};
use crate::audit::{AuditEvent, LogLevel};
use crate::loa::LOA;

/// Structured result for each canon load attempt
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonLoadResult {
    pub entry_id: String,
    pub success: bool,
    pub message: String,
    pub timestamp: chrono::DateTime<Utc>,
}

/// Runs the canon initializer tool, loading trusted entries from disk.
/// Returns structured log results or exits on critical failure.
pub fn run_loader(
    file_path: &str,
    license_token: &str,
    data_dir: &str,
    log_path: &str,
    trace_id: Option<String>,
) -> Result<Vec<CanonLoadResult>, String> {
    let config = load_config();
    let session = Arc::new(SessionContext::new(config.clone(), Some(license_token)));

    if session.loa != LOA::Root {
        return Err("LOA::Root required to run canon_init_tool.".into());
    }

    let mut file = File::open(Path::new(file_path)).map_err(|_| "Unable to open canon data file")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).map_err(|_| "Failed to read canon file")?;

    let entries: Vec<TrustedKnowledgeEntry> =
        serde_json::from_str(&contents).map_err(|_| "Invalid canon file format")?;

    let mut store = CanonStoreSled::new(data_dir, config.trust.allow_operator_canon_write);
    let mut results = Vec::new();

    for mut entry in entries {
        entry.verdict = SigilVerdict::Allow;

        let audit = AuditEvent::new(
            &session.session_id,
            "canon_init",
            &entry.id,
            trace_id.clone().unwrap_or_else(|| "canon-load-init".into()),
        )
        .with_severity(LogLevel::Info)
        .from_source("canon_init_tool")
        .with_context("Canon bootstrapping entry load");

        let audit_write_result = audit
            .clone()
            .write_to_log(log_path)
            .map_err(|_| format!("Audit write failure for entry: {}", entry.id));

        if let Err(err) = audit_write_result {
            results.push(CanonLoadResult {
                entry_id: entry.id.clone(),
                success: false,
                message: err,
                timestamp: Utc::now(),
            });
            continue;
        }

        match store.add_entry(entry, &session.loa, config.trust.allow_operator_canon_write) {
            Ok(_) => results.push(CanonLoadResult {
                entry_id: entry.id.clone(),
                success: true,
                message: "Canon entry loaded".into(),
                timestamp: Utc::now(),
            }),
            Err(e) => results.push(CanonLoadResult {
                entry_id: entry.id.clone(),
                success: false,
                message: format!("Canon write failed: {:?}", e),
                timestamp: Utc::now(),
            }),
        }
    }

    Ok(results)
}
