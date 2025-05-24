// tests/canon_store.rs
use mmf_sigil::canon_store_sled::CanonStoreSled;
use mmf_sigil::trusted_knowledge::TrustedKnowledgeEntry;
use mmf_sigil::loa::LOA;
use mmf_sigil::canon_store::CanonStore;

use tempfile::tempdir;
use std::fs;

#[test]
pub fn write_and_read_entry_roundtrip() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let path = temp_dir.path().to_str().expect("invalid temp path");

    let store = CanonStoreSled::new(path, true, None);
    let id = "unit_test_doc";

    let entry = TrustedKnowledgeEntry {
        model_id: Some("test_model".to_string()),
        allowed: true,
        score: 0.95,
        threshold: Some(0.8),
        trace_id: Some("trace-123".to_string()),
    };

    let loa = LOA::Root;

    store.write(id, &entry, &loa).expect("write failed");

    let retrieved = store.read(id, &loa).expect("read failed");

    assert!(retrieved.is_some());
    let item = retrieved.unwrap();
    assert_eq!(item.allowed, true);
    assert_eq!(item.model_id.unwrap(), "test_model");
}

#[test]
pub fn reject_read_without_permission() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let path = temp_dir.path().to_str().unwrap();

    let store = CanonStoreSled::new(path, true, None);

    let entry = TrustedKnowledgeEntry {
        model_id: None,
        allowed: false,
        score: 0.3,
        threshold: None,
        trace_id: None,
    };

    store.write("restricted", &entry, &LOA::Root).unwrap();

    let result = store.read("restricted", &LOA::Public);
    assert!(result.is_err());
}