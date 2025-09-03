use crate::canon_store::CanonStore;
use crate::canonical_record::CanonicalRecord;
use crate::loa::LOA;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Compute a basic semantic diff between two CanonicalRecords
pub fn semantic_diff(a: &CanonicalRecord, b: &CanonicalRecord) -> HashMap<String, String> {
    let mut diffs = HashMap::new();

    if a.schema_version != b.schema_version {
        diffs.insert(
            "schema_version".into(),
            format!("{} -> {}", a.schema_version, b.schema_version),
        );
    }

    if a.kind != b.kind {
        diffs.insert("kind".into(), format!("{} -> {}", a.kind, b.kind));
    }

    if a.tenant != b.tenant {
        diffs.insert("tenant".into(), format!("{} -> {}", a.tenant, b.tenant));
    }

    if a.space != b.space {
        diffs.insert("space".into(), format!("{} -> {}", a.space, b.space));
    }

    if a.hash != b.hash {
        diffs.insert("hash".into(), format!("{} -> {}", a.hash, b.hash));
    }

    if a.payload != b.payload {
        diffs.insert("payload".into(), "Payload content changed".into());
    }

    if a.sig != b.sig {
        diffs.insert("sig".into(), "Signature changed".into());
    }

    if a.pub_key != b.pub_key {
        diffs.insert("pub_key".into(), "Public key changed".into());
    }

    diffs
}

/// Diff a Canon record by ID using CanonStore
/// This compares the current record with its predecessor (prev field)
pub fn diff_by_id_with_store(
    canon_store: Arc<Mutex<dyn CanonStore>>,
    id: &str,
    requester_loa: &LOA,
) -> Result<HashMap<String, String>, String> {
    let store = canon_store
        .lock()
        .map_err(|_| "Failed to acquire canon store lock".to_string())?;

    // Load the current record
    let current_record = store.load_record(id, requester_loa).ok_or_else(|| {
        format!(
            "Record with ID '{}' not found or insufficient permissions",
            id
        )
    })?;

    // Check if there's a previous version
    if let Some(prev_id) = &current_record.prev {
        let previous_record = store.load_record(prev_id, requester_loa).ok_or_else(|| {
            format!(
                "Previous record with ID '{}' not found or insufficient permissions",
                prev_id
            )
        })?;

        Ok(semantic_diff(&previous_record, &current_record))
    } else {
        Ok(HashMap::from([(
            "status".into(),
            "No previous version found - this is the initial record".into(),
        )]))
    }
}

/// Legacy diff_by_id function that uses file-based operations
/// Deprecated: Use diff_by_id_with_store instead
#[deprecated(note = "Use diff_by_id_with_store with CanonStore instead")]
pub fn diff_by_id(_id: &str) -> Result<HashMap<String, String>, String> {
    Err("Legacy file-based diff is deprecated. Use CanonStore-based diff instead.".into())
}
