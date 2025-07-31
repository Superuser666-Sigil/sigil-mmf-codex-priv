// tests/canon_store.rs
use mmf_sigil::canon_store_sled::CanonStoreSled;
use mmf_sigil::trusted_knowledge::TrustedKnowledgeEntry;
use mmf_sigil::loa::LOA;
use mmf_sigil::canon_store::CanonStore;

use tempfile::tempdir;
use std::fs;

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

    store.add_entry(entry.clone(), &loa, true).expect("should be able to write entry");

    let retrieved = store.load_entry(id, &loa);

    assert!(retrieved.is_some(), "should retrieve the stored entry");
    let item = retrieved.expect("retrieved item should be Some");
    assert_eq!(item.verdict, crate::trusted_knowledge::SigilVerdict::Allow);
    assert_eq!(item.id, "unit_test_doc");
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

    store.add_entry(entry, &LOA::Root, true).expect("should be able to write restricted entry");

    let result = store.load_entry("restricted", &LOA::Guest);  // Try to access with guest LOA
    assert!(result.is_none(), "guest should not be able to access root-required entry");
}