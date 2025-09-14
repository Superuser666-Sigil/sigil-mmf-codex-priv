// tests/canon_store.rs
use crate::canon_store::CanonStore;
use crate::canon_store_sled_encrypted::CanonStoreSled as EncryptedCanonStoreSled;
use crate::keys::KeyManager;
use crate::canonical_record::CanonicalRecord;
use crate::loa::LOA;
use crate::trusted_knowledge::TrustedKnowledgeEntry;

use tempfile::tempdir;

#[test]
pub fn write_and_read_entry_roundtrip() {
    let temp_dir = tempdir().expect("should be able to create temp dir for test");
    let path = temp_dir
        .path()
        .to_str()
        .expect("temp path should be valid UTF-8");

    let encryption_key = KeyManager::get_encryption_key().expect("encryption key");
    let mut store = EncryptedCanonStoreSled::new(path, &encryption_key)
        .expect("should be able to create encrypted CanonStore");
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
    let record =
        CanonicalRecord::from_trusted_entry(&entry, "test", "user", 1).expect("canonicalize");
    store
        .add_record(record, &loa, true)
        .expect("should be able to write entry");
    // Load the record back
    let retrieved = store.load_record(id, &loa);
    assert!(retrieved.is_some(), "should retrieve the stored record");
    let rec = retrieved.unwrap();
    // Deserialize payload back into TrustedKnowledgeEntry for verification
    let tk: TrustedKnowledgeEntry =
        serde_json::from_value(rec.payload).expect("deserialize payload");
    assert_eq!(tk.verdict, crate::trusted_knowledge::SigilVerdict::Allow);
    assert_eq!(tk.id, "unit_test_doc");
}

#[test]
pub fn reject_read_without_permission() {
    let temp_dir = tempdir().expect("should be able to create temp dir for test");
    let path = temp_dir
        .path()
        .to_str()
        .expect("temp path should be valid UTF-8");

    let encryption_key = KeyManager::get_encryption_key().expect("encryption key");
    let mut store = EncryptedCanonStoreSled::new(path, &encryption_key)
        .expect("should be able to create encrypted CanonStore");

    let entry = TrustedKnowledgeEntry {
        id: "restricted".to_string(),
        loa_required: LOA::Root, // Requires root access
        verdict: crate::trusted_knowledge::SigilVerdict::Deny,
        category: "restricted".to_string(),
        content: "restricted content".to_string(),
    };

    let record =
        CanonicalRecord::from_trusted_entry(&entry, "test", "user", 1).expect("canonicalize");
    store
        .add_record(record, &LOA::Root, true)
        .expect("should be able to write restricted record");
    let result = store.load_record("restricted", &LOA::Guest); // Try to access with guest LOA
    assert!(
        result.is_none(),
        "guest should not be able to access root-required record"
    );
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
    let canon1 = record1
        .to_canonical_json()
        .expect("Failed to canonicalize record1");
    let canon2 = record1
        .to_canonical_json()
        .expect("Failed to canonicalize record1 again");

    // The same record should produce identical canonical JSON when canonicalized multiple times
    assert_eq!(
        canon1, canon2,
        "JCS canonicalization should be deterministic for the same record"
    );

    // Verify that the canonical JSON is actually canonical (sorted keys)
    let parsed1: serde_json::Value =
        serde_json::from_str(&canon1).expect("Failed to parse canonical JSON");
    let parsed2: serde_json::Value =
        serde_json::from_str(&canon2).expect("Failed to parse canonical JSON");

    assert_eq!(
        parsed1, parsed2,
        "Parsed canonical JSON should be identical"
    );

    // Test that the canonical JSON has sorted keys (this is the main purpose of canonicalization)
    if let serde_json::Value::Object(map) = &parsed1 {
        let keys: Vec<&String> = map.keys().collect();
        let mut sorted_keys = keys.clone();
        sorted_keys.sort();
        assert_eq!(keys, sorted_keys, "Canonical JSON should have sorted keys");
    }
}

#[test]
fn test_canon_write_verify_round_trip_with_quorum() {
    use crate::canon_store_sled_encrypted::CanonStoreSled as EncryptedCanonStoreSled;
    use crate::canonical_record::CanonicalRecord;
    use crate::keys::{CanonSigningKey, KeyManager};
    use crate::quorum_system::QuorumSystem;
    use crate::witness_registry::WitnessRegistry;
    use base64::Engine;
    use chrono::Utc;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use std::sync::{Arc, Mutex};

    let temp_dir = tempdir().expect("should be able to create temp dir for test");
    let path = temp_dir
        .path()
        .to_str()
        .expect("temp path should be valid UTF-8");

    // Use proper key management for encryption key
    let encryption_key =
        KeyManager::get_encryption_key().expect("should be able to get encryption key");

    // Use encrypted store with proper key management
    let canon_store = Arc::new(Mutex::new(
        EncryptedCanonStoreSled::new(path, &encryption_key)
            .expect("should be able to create encrypted store"),
    ));

    println!("📋 Setting up test licenses for Root + three Mentors (TEST LICENSES ONLY)");

    // Create witness registry and add test witnesses
    let witness_registry = Arc::new(
        WitnessRegistry::new(canon_store.clone()).expect("should create witness registry"),
    );

    // Generate three mentor witness keys
    let mentor_keys: Vec<_> = (0..3)
        .map(|i| {
            let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
            let public_key_b64 = base64::engine::general_purpose::STANDARD
                .encode(signing_key.verifying_key().as_bytes());
            let witness_id = format!("test_mentor_{}", i + 1);

            println!(
                "🔑 Generated TEST Mentor {} license (public key: {})",
                i + 1,
                &public_key_b64[..16]
            );

            // Add witness to registry
            witness_registry
                .add_witness(
                    witness_id.clone(),
                    public_key_b64,
                    "TEST_AUTHORITY_MENTOR".to_string(),
                    format!("TEST LICENSE ONLY - Mentor {} for test quorum", i + 1),
                    &LOA::Root,
                )
                .expect("should add test mentor witness");

            (witness_id, signing_key)
        })
        .collect();

    // Create test record requiring quorum approval
    let payload = serde_json::json!({
        "key": "critical_system_config",
        "value": "updated_trust_model_v2",
        "session_id": "test_quorum_session",
        "note": "This is a test canon write requiring Root + 3 Mentor witnesses"
    });

    let mut record = CanonicalRecord {
        kind: "system_config".to_string(),
        schema_version: 1,
        id: "critical_system_config".to_string(),
        tenant: "system".to_string(),
        ts: Utc::now(),
        space: "system".to_string(),
        payload,
        links: vec![],
        prev: None,
        hash: String::new(), // Will be computed
        sig: None,           // Will be signed
        pub_key: None,       // Will be set from key store
        witnesses: vec![],
    };

    // Step 1: Create quorum proposal for this canon write
    let mut quorum_system = QuorumSystem::new(witness_registry.clone());
    let proposal_id = quorum_system
        .create_proposal(
            record.id.clone(),
            serde_json::to_string(&record.payload).expect("serialize payload"),
            3, // Require 3 mentor signatures
        )
        .expect("should create proposal");

    println!(
        "📝 Created quorum proposal {} requiring 3 signatures",
        proposal_id
    );

    // Step 2: Get the proposal content hash for witnesses to sign
    let content_hash_bytes = {
        let proposal = quorum_system
            .get_proposal(&proposal_id)
            .expect("proposal should exist");
        proposal.content_hash.clone()
    };

    // Step 3: Collect signatures from the three mentors
    println!("✍️  Collecting signatures from test mentors...");
    for (i, (witness_id, signing_key)) in mentor_keys.iter().enumerate() {
        let signature = signing_key.sign(content_hash_bytes.as_bytes());
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

        quorum_system
            .add_signature(&proposal_id, witness_id.clone(), signature_b64)
            .expect("should add mentor signature");

        println!("   ✅ Mentor {} signed proposal", i + 1);
    }

    // Step 4: Verify quorum is reached
    let final_proposal = quorum_system
        .get_proposal(&proposal_id)
        .expect("proposal should exist");
    assert!(final_proposal.has_quorum(), "should have reached quorum");
    println!(
        "🎯 Quorum reached! {} of {} required signatures collected",
        final_proposal.get_signature_count(),
        final_proposal.required_k
    );

    // Step 5: Now we can canonicalize → hash → sign → persist with proper authorization
    let canonical_json = record
        .to_canonical_json()
        .expect("canonicalization should succeed");

    // Compute hash
    let mut hasher = Sha256::new();
    hasher.update(canonical_json.as_bytes());
    let digest = hasher.finalize();
    record.hash = hex::encode(digest);

    // Sign with Root's key
    let root_signing_key = CanonSigningKey::generate();
    let (signature, public_key) = root_signing_key.sign_record(canonical_json.as_bytes());

    record.sig = Some(signature);
    record.pub_key = Some(public_key);

    // Add witness records from the quorum
    for witness_sig in &final_proposal.signers {
        record
            .witnesses
            .push(crate::canonical_record::WitnessRecord {
                witness_id: witness_sig.witness_id.clone(),
                signature: witness_sig.signature.clone(),
                timestamp: witness_sig.signed_at,
                authority: "TEST_MENTOR_QUORUM".to_string(),
            });
    }

    // Step 6: Persist CanonicalRecord with proper quorum authorization
    let mut store_guard = canon_store.lock().expect("should lock store");
    store_guard
        .add_record(record.clone(), &LOA::Root, true) // allow_operator_write=true for system space
        .expect("should be able to write record with proper quorum");
    drop(store_guard);

    // Step 7: Reload and verify
    let store_guard = canon_store.lock().expect("should lock store for read");
    let reloaded_record = store_guard
        .load_record("critical_system_config", &LOA::Root)
        .expect("should be able to reload record");
    drop(store_guard);

    // Step 8: Verify signature integrity
    assert_eq!(reloaded_record.hash, record.hash, "hash should match");
    assert_eq!(reloaded_record.sig, record.sig, "signature should match");
    assert_eq!(
        reloaded_record.pub_key, record.pub_key,
        "public key should match"
    );
    assert_eq!(
        reloaded_record.witnesses.len(),
        3,
        "should have 3 witness signatures"
    );

    // Verify the Root signature is valid
    let reloaded_canonical = reloaded_record
        .to_canonical_json()
        .expect("reloaded record should canonicalize");

    let reloaded_signature = reloaded_record
        .sig
        .as_ref()
        .expect("signature should exist");
    root_signing_key
        .verify_signature(reloaded_canonical.as_bytes(), reloaded_signature)
        .expect("Root signature should be valid");

    // Verify each witness signature
    for (i, witness_record) in reloaded_record.witnesses.iter().enumerate() {
        let is_valid = witness_registry
            .validate_witness_signature(
                &witness_record.witness_id,
                content_hash_bytes.as_bytes(),
                &witness_record.signature,
            )
            .expect("should validate witness signature");
        assert!(is_valid, "Mentor {} signature should be valid", i + 1);
    }

    // Verify hash integrity
    let mut recomputed_hasher = Sha256::new();
    recomputed_hasher.update(reloaded_canonical.as_bytes());
    let recomputed_digest = recomputed_hasher.finalize();
    let recomputed_hash = hex::encode(recomputed_digest);

    assert_eq!(
        reloaded_record.hash, recomputed_hash,
        "recomputed hash should match stored hash"
    );

    // Verify payload integrity
    assert_eq!(
        reloaded_record.payload, record.payload,
        "payload should be intact"
    );
    assert_eq!(
        reloaded_record.kind, "system_config",
        "kind should be preserved"
    );
    assert_eq!(
        reloaded_record.tenant, "system",
        "tenant should be preserved"
    );
    assert_eq!(reloaded_record.space, "system", "space should be preserved");

    println!("✅ Canon write/verify round-trip test with proper quorum PASSED");
    println!("🔒 Verified: Root signature + 3 Mentor witness signatures + hash integrity");
}
