//! Tests for witness quorum enforcement in Canon write paths

use crate::canon_store::CanonStore;
use crate::canon_store_sled_encrypted::CanonStoreSled as EncryptedCanonStoreSled;
use crate::canonical_record::CanonicalRecord;
use crate::keys::{CanonSigningKey, KeyManager};
use crate::loa::LOA;
use crate::quorum_system::QuorumSystem;
use crate::witness_registry::WitnessRegistry;
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

#[test]
fn test_quorum_enforcement_blocks_system_writes_without_quorum() {
    let temp_dir = TempDir::new().expect("should create temp dir");
    let path = temp_dir.path().to_str().expect("temp path should be valid");

    // Set up encrypted canon store
    let encryption_key = KeyManager::dev_key_for_testing().expect("should get encryption key");
    let canon_store = Arc::new(Mutex::new(
        EncryptedCanonStoreSled::new(path, &encryption_key).expect("should create encrypted store"),
    ));

    // Set up witness registry with test witnesses
    let witness_registry = Arc::new(
        WitnessRegistry::new(canon_store.clone()).expect("should create witness registry"),
    );

    // Generate test mentor witnesses (but not enough for quorum)
    let signing_key1 = SigningKey::generate(&mut rand::rngs::OsRng);
    let public_key1_b64 =
        base64::engine::general_purpose::STANDARD.encode(signing_key1.verifying_key().as_bytes());

    witness_registry
        .add_witness(
            "test_mentor_1".to_string(),
            public_key1_b64,
            "TEST_AUTHORITY".to_string(),
            "Test mentor 1".to_string(),
            &LOA::Root,
        )
        .expect("should add witness");

    // Create quorum system
    let mut quorum_system = QuorumSystem::new(witness_registry.clone());

    // Try to create a system proposal requiring 3 signatures (but we only have 1 witness)
    let proposal_id = quorum_system
        .create_proposal(
            "system_config_update".to_string(),
            "critical_system_setting=new_value".to_string(),
            3, // Require 3 signatures but we only have 1 witness
        )
        .expect("should create proposal");

    // Add one signature (not enough for quorum)
    let proposal = quorum_system
        .get_proposal(&proposal_id)
        .expect("proposal should exist");
    let content_hash = proposal.content_hash.clone();

    let signature = signing_key1.sign(content_hash.as_bytes());
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

    quorum_system
        .add_signature(&proposal_id, "test_mentor_1".to_string(), signature_b64)
        .expect("should add signature");

    // Verify that quorum is NOT reached
    let proposal = quorum_system
        .get_proposal(&proposal_id)
        .expect("proposal should exist");
    assert!(
        !proposal.has_quorum(),
        "should not have quorum with only 1 of 3 required signatures"
    );

    // Attempt to commit should fail
    let commit_result = quorum_system.commit_proposal(&proposal_id);
    assert!(commit_result.is_err(), "commit should fail without quorum");

    // Verify the error message mentions insufficient signatures
    let error_msg = format!("{:?}", commit_result.unwrap_err());
    assert!(
        error_msg.contains("requires 3 signatures"),
        "error should mention signature requirement"
    );

    println!("✅ Verified: System writes are blocked without sufficient quorum");
}

#[test]
fn test_quorum_enforcement_allows_system_writes_with_quorum() {
    let temp_dir = TempDir::new().expect("should create temp dir");
    let path = temp_dir.path().to_str().expect("temp path should be valid");

    // Set up encrypted canon store
    let encryption_key = KeyManager::dev_key_for_testing().expect("should get encryption key");
    let canon_store = Arc::new(Mutex::new(
        EncryptedCanonStoreSled::new(path, &encryption_key).expect("should create encrypted store"),
    ));

    // Set up witness registry with sufficient test witnesses
    let witness_registry = Arc::new(
        WitnessRegistry::new(canon_store.clone()).expect("should create witness registry"),
    );

    // Generate 3 test mentor witnesses
    let mentor_keys: Vec<_> = (0..3)
        .map(|i| {
            let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
            let public_key_b64 = base64::engine::general_purpose::STANDARD
                .encode(signing_key.verifying_key().as_bytes());
            let witness_id = format!("test_mentor_{}", i + 1);

            witness_registry
                .add_witness(
                    witness_id.clone(),
                    public_key_b64,
                    "TEST_AUTHORITY".to_string(),
                    format!("Test mentor {}", i + 1),
                    &LOA::Root,
                )
                .expect("should add witness");

            (witness_id, signing_key)
        })
        .collect();

    // Create quorum system
    let mut quorum_system = QuorumSystem::new(witness_registry.clone());

    // Create a system proposal requiring 3 signatures
    let proposal_id = quorum_system
        .create_proposal(
            "system_config_update".to_string(),
            "critical_system_setting=new_value".to_string(),
            3, // Require 3 signatures and we have 3 witnesses
        )
        .expect("should create proposal");

    // Collect all 3 required signatures
    let proposal = quorum_system
        .get_proposal(&proposal_id)
        .expect("proposal should exist");
    let content_hash = proposal.content_hash.clone();

    for (witness_id, signing_key) in &mentor_keys {
        let signature = signing_key.sign(content_hash.as_bytes());
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

        quorum_system
            .add_signature(&proposal_id, witness_id.clone(), signature_b64)
            .expect("should add signature");
    }

    // Verify that quorum IS reached
    let proposal = quorum_system
        .get_proposal(&proposal_id)
        .expect("proposal should exist");
    assert!(
        proposal.has_quorum(),
        "should have quorum with 3 of 3 required signatures"
    );

    // Commit should succeed
    let committed_proposal = quorum_system
        .commit_proposal(&proposal_id)
        .expect("commit should succeed with quorum");

    // Verify the proposal was properly committed
    assert_eq!(committed_proposal.entry, "system_config_update");
    assert_eq!(
        committed_proposal.content,
        "critical_system_setting=new_value"
    );
    assert_eq!(committed_proposal.signers.len(), 3);

    // Verify the proposal is no longer in the pending list
    assert!(
        quorum_system.get_proposal(&proposal_id).is_none(),
        "committed proposal should be removed from pending"
    );

    println!("✅ Verified: System writes are allowed with sufficient quorum");
}

#[test]
fn test_user_space_writes_bypass_quorum() {
    let temp_dir = TempDir::new().expect("should create temp dir");
    let path = temp_dir.path().to_str().expect("temp path should be valid");

    // Set up encrypted canon store
    let encryption_key = KeyManager::dev_key_for_testing().expect("should get encryption key");
    let mut canon_store =
        EncryptedCanonStoreSled::new(path, &encryption_key).expect("should create encrypted store");

    // Create a user-space record (should not require quorum)
    let payload = serde_json::json!({
        "key": "user_preference",
        "value": "dark_mode_enabled",
        "session_id": "user_session_123"
    });

    let mut record = CanonicalRecord {
        kind: "user_data".to_string(),
        schema_version: 1,
        id: "user_preference".to_string(),
        tenant: "user".to_string(),
        ts: Utc::now(),
        space: "user".to_string(), // User space
        payload,
        links: vec![],
        prev: None,
        hash: String::new(),
        sig: None,
        pub_key: None,
        witnesses: vec![], // No witnesses required for user space
    };

    // Canonicalize and sign the record
    let canonical_json = record
        .to_canonical_json()
        .expect("canonicalization should succeed");

    let mut hasher = Sha256::new();
    hasher.update(canonical_json.as_bytes());
    let digest = hasher.finalize();
    record.hash = hex::encode(digest);

    let signing_key = CanonSigningKey::generate();
    let (signature, public_key) = signing_key.sign_record(canonical_json.as_bytes());

    record.sig = Some(signature);
    record.pub_key = Some(public_key);

    // User space write should succeed with Operator LOA (no quorum required for user space)
    let result = canon_store.add_record(record.clone(), &LOA::Operator, false);
    if let Err(e) = &result {
        println!("User space write failed with error: {}", e);
    }
    assert!(
        result.is_ok(),
        "user space write should succeed without quorum"
    );

    // Verify the record can be read back
    let reloaded = canon_store.load_record("user_preference", &LOA::Operator);
    assert!(reloaded.is_some(), "user record should be readable");

    let reloaded_record = reloaded.unwrap();
    assert_eq!(reloaded_record.space, "user");
    assert_eq!(reloaded_record.tenant, "user");
    assert_eq!(reloaded_record.witnesses.len(), 0); // No witnesses required

    println!("✅ Verified: User space writes bypass quorum requirements");
}
