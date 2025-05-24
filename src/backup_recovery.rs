// Phase 1 - Refactoring Sigil: backup_recovery.rs
// Purpose: Snapshot recovery utility with LOA-gated CanonStore writes, structured audit events, and Rule Zero reasoning

use std::fs::File;
use std::io::Read;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::trusted_knowledge::TrustedKnowledgeEntry;
use crate::sigil_vault::VaultMemoryBlock;
use crate::canon_store::CanonStore;
use crate::audit::{AuditEvent, LogLevel};
use crate::loa::LOA;

/// A deserialized snapshot containing trusted vault + Canon knowledge.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigilSnapshot {
    pub vault: Vec<VaultMemoryBlock>,
    pub canon: Vec<TrustedKnowledgeEntry>,
}

/// A structured log entry for each Canon restore operation.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreLog {
    pub entry_index: usize,
    pub success: bool,
    pub message: String,
    pub loa_applied: String,
    pub timestamp: DateTime<Utc>,
    pub reason: Option<String>, // Canon traceable reason for restore outcome
}

/// Trait that defines permission for restoring snapshots.
pub trait SnapshotRestoreAccess {
    fn can_restore_snapshot(&self) -> bool;
}

impl SnapshotRestoreAccess for LOA {
    fn can_restore_snapshot(&self) -> bool {
        matches!(self, LOA::Mentor | LOA::Root)
    }
}

/// Canon-traceable policy error from backup recovery operation.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleZeroError {
    pub category: String,
    pub loa_level: String,
    pub message: String,
    pub timestamp: DateTime<Utc>,
    pub trust_trace: String,
}

#[derive(Debug)]
pub enum RestorePolicyError {
    Unauthorized(RuleZeroError),
    Io(RuleZeroError),
    Parse(RuleZeroError),
    Store(RuleZeroError),
}

/// Attempts to restore a snapshot with full Rule Zero traceable logic.
/// Emits structured audit events and embeds reasoning chain per result.
pub fn restore_snapshot<T: CanonStore, A: SnapshotRestoreAccess>(
    store: &T,
    loa: &A,
    path: &str,
) -> Result<Vec<RestoreLog>, RestorePolicyError> {
    let now = Utc::now();

    if !loa.can_restore_snapshot() {
        return Err(RestorePolicyError::Unauthorized(RuleZeroError {
            category: "policy_violation".into(),
            loa_level: format!("{:?}", loa),
            message: "LOA not authorized to perform snapshot restore.".into(),
            timestamp: now,
            trust_trace: json!({
                "decision": "deny",
                "loa": format!("{:?}", loa),
                "required": "Mentor or Root",
                "action": "restore_snapshot"
            }).to_string(),
        }));
    }

    let mut file = File::open(path).map_err(|e| {
        RestorePolicyError::Io(RuleZeroError {
            category: "io_error".into(),
            loa_level: format!("{:?}", loa),
            message: format!("Failed to open file: {}", e),
            timestamp: now,
            trust_trace: json!({
                "file_path": path,
                "error": e.to_string(),
                "action": "open_snapshot"
            }).to_string(),
        })
    })?;

    let mut content = String::new();
    file.read_to_string(&mut content).map_err(|e| {
        RestorePolicyError::Io(RuleZeroError {
            category: "read_failure".into(),
            loa_level: format!("{:?}", loa),
            message: format!("Failed to read file content: {}", e),
            timestamp: now,
            trust_trace: json!({
                "action": "read_snapshot",
                "file": path,
                "error": e.to_string()
            }).to_string(),
        })
    })?;

    let snapshot: SigilSnapshot = serde_json::from_str(&content).map_err(|e| {
        RestorePolicyError::Parse(RuleZeroError {
            category: "parse_failure".into(),
            loa_level: format!("{:?}", loa),
            message: format!("Failed to parse snapshot: {}", e),
            timestamp: now,
            trust_trace: json!({
                "error": e.to_string(),
                "action": "deserialize_snapshot"
            }).to_string(),
        })
    })?;

    let mut logs = Vec::new();
    for (i, entry) in snapshot.canon.into_iter().enumerate() {
        let ts = Utc::now();
        let id = format!("{}::{}", entry.category, entry.key);

        match store.write(&id, &entry, loa) {
            Ok(_) => {
                logs.push(RestoreLog {
                    entry_index: i,
                    success: true,
                    message: "Restored successfully.".into(),
                    loa_applied: format!("{:?}", loa),
                    timestamp: ts,
                    reason: Some(json!({
                        "action": "write_entry",
                        "entry": id,
                        "decision": "allow",
                        "loa": format!("{:?}", loa)
                    }).to_string()),
                });

                let _ = AuditEvent::new("recovery", "restore_entry", &id, path)
                    .with_severity(LogLevel::Info)
                    .with_context("Canon snapshot restore successful")
                    .write_to_log();
            }
            Err(e) => {
                logs.push(RestoreLog {
                    entry_index: i,
                    success: false,
                    message: format!("Restore failed: {:?}", e),
                    loa_applied: format!("{:?}", loa),
                    timestamp: ts,
                    reason: Some(json!({
                        "action": "write_entry",
                        "entry": id,
                        "decision": "error",
                        "error": format!("{:?}", e)
                    }).to_string()),
                });

                let _ = AuditEvent::new("recovery", "restore_failed", &id, path)
                    .with_severity(LogLevel::Warn)
                    .with_context(format!("Snapshot recovery failure: {:?}", e))
                    .write_to_log();
            }
        }
    }

    Ok(logs)
}
