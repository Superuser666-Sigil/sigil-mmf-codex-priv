use crate::canonical_record::CanonicalRecord;
use crate::errors::{SigilError, SigilResult};
use crate::loa::LOA;
use std::sync::{Arc, Mutex};

pub trait CanonStore: Send + Sync {
    /// Load a canonical record by key.  Returns None if the caller's LOA
    /// does not meet the record's loa_required or if the record is not found.
    fn load_record(&self, key: &str, loa: &LOA) -> Option<CanonicalRecord>;

    /// Add a canonical record to the store.  The caller must have
    /// sufficient LOA to write to the target namespace.  The
    /// `allow_operator_write` flag permits Operator LOA to write into
    /// system space when true.
    fn add_record(
        &mut self,
        record: CanonicalRecord,
        loa: &LOA,
        allow_operator_write: bool,
    ) -> Result<(), &'static str>;

    /// List canonical records filtered by kind.  Returns an empty list if
    /// the caller lacks read permissions.  If kind is None, all
    /// records visible to the caller are returned.
    fn list_records(&self, kind: Option<&str>, loa: &LOA) -> Vec<CanonicalRecord>;
}

/// Revert a Canon record to a previous version using CanonStore
/// This searches through the record's lineage chain to find the target hash
pub fn revert_node_with_store(
    canon_store: Arc<Mutex<dyn CanonStore>>,
    id: &str,
    to_hash: &str,
    requester_loa: &LOA,
) -> SigilResult<()> {
    let mut store = canon_store
        .lock()
        .map_err(|_| SigilError::internal("Failed to acquire canon store lock"))?;

    // Only Root can revert records
    if !matches!(requester_loa, LOA::Root) {
        return Err(SigilError::insufficient_loa(
            LOA::Root,
            requester_loa.clone(),
        ));
    }

    // Load the current record
    let current_record = store
        .load_record(id, requester_loa)
        .ok_or_else(|| SigilError::not_found("record", id))?;

    // Search through the lineage chain to find the target hash
    let mut target_record = None;
    let mut search_id = Some(id.to_string());

    while let Some(current_id) = search_id {
        if let Some(record) = store.load_record(&current_id, requester_loa) {
            if record.hash == to_hash {
                target_record = Some(record);
                break;
            }
            search_id = record.prev;
        } else {
            break;
        }
    }

    let target = target_record.ok_or_else(|| SigilError::not_found("record with hash", to_hash))?;

    // Create a new record based on the target but with updated metadata
    let reverted_record = CanonicalRecord {
        id: current_record.id.clone(),
        kind: target.kind,
        schema_version: target.schema_version,
        tenant: target.tenant,
        ts: chrono::Utc::now(),
        space: target.space,
        payload: target.payload,
        links: target.links,
        prev: Some(current_record.id.clone()), // Link to the current record as previous
        hash: String::new(),                   // Will be computed during canonicalization
        sig: None,                             // Will be signed during persistence
        pub_key: None,                         // Will be set during persistence
        witnesses: Vec::new(),
    };

    // Add the reverted record to the store
    store
        .add_record(reverted_record, requester_loa, false)
        .map_err(|e| SigilError::canon("revert", e))?;

    Ok(())
}

/// Legacy revert_node function that uses file-based operations
/// Deprecated: Use revert_node_with_store instead
#[deprecated(note = "Use revert_node_with_store with CanonStore instead")]
pub fn revert_node(_id: &str, _to_hash: &str) -> Result<(), String> {
    Err("Legacy file-based revert is deprecated. Use CanonStore-based revert instead.".into())
}
