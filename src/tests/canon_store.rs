// tests/canon_store.rs
use crate::canon_store_sled::CanonStoreSled;
use crate::trusted_knowledge::TrustedKnowledgeEntry;
use crate::loa::LOA;
use crate::canon_store::CanonStore;
use crate::canonical_record::CanonicalRecord;

use tempfile::tempdir;


#[test]
pub fn write_and_read_entry_roundtrip() {
    let temp_dir = tempdir().expect("should be able to create temp dir for test");
    let path = temp_dir.path().to_str().expect("temp path should be valid UTF-8");

    let mut store = CanonStoreSled::new(path).expect("should be able to create CanonStoreSled");
    let id = "unit_test_doc";

    let entry = TrustedKnowledgeEntry {
        id: id.to_string(),
        loa_required: LOA::Observer,
        verdict: crate::trusted_knowledge::SigilVerdict::Allow,
        category: "test".to_string(),
        content: "test content".to_string(),
    };

    let loa = LOA::Root;

    // Convert the TrustedKnowledgeEntry to a canonical record and store it
    let record = CanonicalRecord::from_trusted_entry(&entry, "test", "user", 1).expect("canonicalize");
    store.add_record(record, &loa, true).expect("should be able to write entry");
    // Load the record back
    let retrieved = store.load_record(id, &loa);
    assert!(retrieved.is_some(), "should retrieve the stored record");
    let rec = retrieved.unwrap();
    // Deserialize payload back into TrustedKnowledgeEntry for verification
    let tk: TrustedKnowledgeEntry = serde_json::from_value(rec.payload).expect("deserialize payload");
    assert_eq!(tk.verdict, crate::trusted_knowledge::SigilVerdict::Allow);
    assert_eq!(tk.id, "unit_test_doc");
}

#[test]
pub fn reject_read_without_permission() {
    let temp_dir = tempdir().expect("should be able to create temp dir for test");
    let path = temp_dir.path().to_str().expect("temp path should be valid UTF-8");

    let mut store = CanonStoreSled::new(path).expect("should be able to create CanonStoreSled");

    let entry = TrustedKnowledgeEntry {
        id: "restricted".to_string(),
        loa_required: LOA::Root,  // Requires root access
        verdict: crate::trusted_knowledge::SigilVerdict::Deny,
        category: "restricted".to_string(),
        content: "restricted content".to_string(),
    };

    let record = CanonicalRecord::from_trusted_entry(&entry, "test", "user", 1).expect("canonicalize");
    store.add_record(record, &LOA::Root, true).expect("should be able to write restricted record");
    let result = store.load_record("restricted", &LOA::Guest);  // Try to access with guest LOA
    assert!(result.is_none(), "guest should not be able to access root-required record");
}

#[test]
fn test_jcs_canonicalization_consistency() {
    // Create a test record
    let entry = TrustedKnowledgeEntry {
        id: "test_id".to_string(),
        loa_required: LOA::Observer,
        verdict: crate::trusted_knowledge::SigilVerdict::Allow,
        category: "test_category".to_string(),
        content: "test_content".to_string(),
    };
    
    let record1 = CanonicalRecord::from_trusted_entry(&entry, "test_tenant", "test_space", 1)
        .expect("Failed to create canonical record");
    
    // Test that the same record produces consistent canonicalization when called multiple times
    let canon1 = record1.to_canonical_json().expect("Failed to canonicalize record1");
    let canon2 = record1.to_canonical_json().expect("Failed to canonicalize record1 again");
    
    // The same record should produce identical canonical JSON when canonicalized multiple times
    assert_eq!(canon1, canon2, "JCS canonicalization should be deterministic for the same record");
    
    // Verify that the canonical JSON is actually canonical (sorted keys)
    let parsed1: serde_json::Value = serde_json::from_str(&canon1).expect("Failed to parse canonical JSON");
    let parsed2: serde_json::Value = serde_json::from_str(&canon2).expect("Failed to parse canonical JSON");
    
    assert_eq!(parsed1, parsed2, "Parsed canonical JSON should be identical");
    
    // Test that the canonical JSON has sorted keys (this is the main purpose of canonicalization)
    if let serde_json::Value::Object(map) = &parsed1 {
        let keys: Vec<&String> = map.keys().collect();
        let mut sorted_keys = keys.clone();
        sorted_keys.sort();
        assert_eq!(keys, sorted_keys, "Canonical JSON should have sorted keys");
    }
}