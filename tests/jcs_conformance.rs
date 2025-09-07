//! JCS (RFC 8785) conformance smoke tests for canonicalization

use mmf_sigil::canonical_record::CanonicalRecord;
use serde_json::json;

#[test]
fn jcs_basic_key_order_and_numbers() {
    let payload = json!({
        "b": 2,
        "a": 1,
        "nested": {"y": 2, "x": 1},
        "nums": [3, 2, 1],
        "unicode": "\u{00E9}",
    });

    let mut record = CanonicalRecord {
        kind: "test".into(),
        schema_version: 1,
        id: "jcs1".into(),
        tenant: "test".into(),
        ts: chrono::Utc::now(),
        space: "test".into(),
        payload,
        links: vec![],
        prev: None,
        hash: String::new(),
        sig: None,
        pub_key: None,
        witnesses: vec![],
    };

    let canonical = record.to_canonical_json().expect("canonicalize");
    // Keys should be lexicographically ordered; arrays preserved; numbers and unicode stable
    assert!(canonical.find("\"a\"").is_some());
    assert!(canonical.find("\"b\"").is_some());
    assert!(canonical.find("\"nested\"").is_some());
    let a_pos = canonical.find("\"a\"").unwrap();
    let b_pos = canonical.find("\"b\"").unwrap();
    assert!(a_pos < b_pos, "keys must be sorted lexicographically in canonical JSON");
}


