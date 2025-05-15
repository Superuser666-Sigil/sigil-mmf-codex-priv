// Phase 0 - Refactoring Sigil: backup_recovery.rs
// Purpose: Canon-aware, telemetry-safe snapshot recovery utility for MMF + Sigil

use std::fs::File;
use std::io::Read;
use std::path::Path;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::trusted_knowledge::TrustedKnowledgeEntry;
use crate::sigil_vault::VaultMemoryBlock;
use crate::canon_store_sled::CanonStoreSled;
use crate::loa::LOA;

/// Deserialized snapshot structure expected from disk
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigilSnapshot {
    pub vault: Vec<VaultMemoryBlock>,
    pub canon: Vec<TrustedKnowledgeEntry>,
}

/// Structured result for each entry restored from snapshot
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreLog {
    pub entry_index: usize,
    pub success: bool,
    pub message: String,
    pub loa_applied: String,
    pub timestamp: DateTime<Utc>,
}

/// Error variants for structured snapshot restoration failures
#[derive(Debug)]
pub enum RestoreError {
    FileUnavailable,
    ReadFailure,
    InvalidFormat,
}

/// Restores canon from snapshot with per-entry telemetry and optional LOA override
pub fn restore_from_snapshot(
    path: &str,
    canon_store: &mut CanonStoreSled,
    allow_operator: bool,
    loa: &LOA
) -> Result<Vec<RestoreLog>, RestoreError> {
    let mut file = File::open(Path::new(path)).map_err(|_| RestoreError::FileUnavailable)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).map_err(|_| RestoreError::ReadFailure)?;

    let snapshot: SigilSnapshot =
        serde_json::from_str(&contents).map_err(|_| RestoreError::InvalidFormat)?;

    let mut logs = Vec::new();

    for (i, entry) in snapshot.canon.into_iter().enumerate() {
        let result = canon_store.add_entry(entry, loa, allow_operator);
        let (success, message) = match result {
            Ok(_) => (true, "Entry restored successfully".to_string()),
            Err(e) => (false, format!("Failed to restore entry: {:?}", e)),
        };

        logs.push(RestoreLog {
            entry_index: i,
            success,
            message,
            loa_applied: format!("{:?}", loa),
            timestamp: Utc::now(),
        });
    }

    // Note: Vault rehydration logic is assumed to be handled externally
    // If vault support is required, a follow-up function should validate and load those blocks

    Ok(logs)
}
