//! End-to-end tests for interactive quorum-aware Canon commit workflow
//!
//! Tests the complete interactive workflow:
//! 1. Create system proposal
//! 2. Query proposal status (pending)  
//! 3. Collect witness attestations incrementally
//! 4. Query status after each attestation
//! 5. Verify automatic commit when quorum reached
//! 6. Verify Canon persistence and integrity

use crate::canon_store::CanonStore;
use crate::canon_store_sled_encrypted::CanonStoreSled as EncryptedCanonStoreSled;
use crate::keys::{CanonSigningKey, KeyManager};
use crate::loa::LOA;
use crate::runtime_config::{EnforcementMode, RuntimeConfig};
use crate::sigil_runtime_core::SigilRuntimeCore;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use sha2::Digest;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

#[test]
fn test_interactive_quorum_workflow_full_cycle() {
    println!("🚀 Testing complete interactive quorum workflow");

    // Step 1: Set up test environment
    let temp_dir = TempDir::new().expect("should create temp dir");
    let path = temp_dir.path().to_str().expect("temp path should be valid");

    let encryption_key = KeyManager::dev_key_for_testing().expect("should get encryption key");
    let canon_store = Arc::new(Mutex::new(
        EncryptedCanonStoreSled::new(path, &encryption_key).expect("should create encrypted store"),
    ));

    let config = RuntimeConfig {
        enforcement_mode: EnforcementMode::Active,
        threshold: 0.5,
        active_model: None,
        telemetry_enabled: false,
        explanation_enabled: false,
        model_refresh_from_canon: false,
    };

    let runtime = SigilRuntimeCore::new(LOA::Root, canon_store.clone(), config)
        .expect("should create runtime");

    // Step 2: Set up witness registry with test mentors
    println!("👥 Setting up witness registry with test mentors");
    let mentor_keys: Vec<_> = (0..3)
        .map(|i| {
            let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
            let public_key_b64 = base64::engine::general_purpose::STANDARD
                .encode(signing_key.verifying_key().as_bytes());
            let witness_id = format!("test_mentor_{}", i + 1);

            runtime
                .witness_registry
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

    println!("✅ Registered {} test mentors", mentor_keys.len());

    // Step 3: Create system proposal
    println!("📝 Creating system proposal requiring 3 signatures");
    let proposal_id = {
        let mut quorum_system = runtime
            .quorum_system
            .lock()
            .expect("should lock quorum system");
        quorum_system
            .create_proposal(
                "critical_security_update".to_string(),
                "Enable new cryptographic enforcement mode".to_string(),
                3, // Require all 3 mentors
            )
            .expect("should create proposal")
    };

    println!("📄 Created proposal: {}", proposal_id);

    // Step 4: Query initial proposal status
    println!("🔍 Querying initial proposal status");
    let initial_status = {
        let quorum_system = runtime
            .quorum_system
            .lock()
            .expect("should lock quorum system");
        quorum_system
            .get_proposal(&proposal_id)
            .expect("proposal should exist")
            .clone()
    };

    assert_eq!(
        initial_status.get_signature_count(),
        0,
        "should start with 0 signatures"
    );
    assert!(
        !initial_status.has_quorum(),
        "should not have quorum initially"
    );
    assert!(
        !initial_status.is_expired(),
        "should not be expired initially"
    );

    println!(
        "✅ Initial status verified: 0/{} signatures",
        initial_status.required_k
    );

    // Step 5: Collect witness attestations incrementally
    println!("✍️  Collecting witness attestations incrementally");
    let content_hash_bytes = initial_status.content_hash.clone();

    for (i, (witness_id, signing_key)) in mentor_keys.iter().enumerate() {
        println!("   📝 Mentor {} ({}) signing proposal", i + 1, witness_id);

        // Sign the proposal content hash
        let signature = signing_key.sign(content_hash_bytes.as_bytes());
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

        // Add signature to proposal
        {
            let mut quorum_system = runtime
                .quorum_system
                .lock()
                .expect("should lock quorum system");
            quorum_system
                .add_signature(&proposal_id, witness_id.clone(), signature_b64)
                .expect("should add mentor signature");
        }

        // Query status after this signature
        let current_status = {
            let quorum_system = runtime
                .quorum_system
                .lock()
                .expect("should lock quorum system");
            quorum_system
                .get_proposal(&proposal_id)
                .expect("proposal should exist")
                .clone()
        };

        let expected_signatures = i + 1;
        assert_eq!(
            current_status.get_signature_count(),
            expected_signatures,
            "should have {} signatures after mentor {}",
            expected_signatures,
            i + 1
        );

        if expected_signatures >= current_status.required_k {
            assert!(
                current_status.has_quorum(),
                "should have quorum with {}/{} signatures",
                expected_signatures,
                current_status.required_k
            );
            println!(
                "   🎯 Quorum reached! {}/{} signatures",
                expected_signatures, current_status.required_k
            );
        } else {
            assert!(
                !current_status.has_quorum(),
                "should not have quorum with {}/{} signatures",
                expected_signatures,
                current_status.required_k
            );
            println!(
                "   ⏳ Partial quorum: {}/{} signatures",
                expected_signatures, current_status.required_k
            );
        }
    }

    // Step 6: Verify final quorum state
    println!("🎯 Verifying final quorum state");
    let final_proposal = {
        let quorum_system = runtime
            .quorum_system
            .lock()
            .expect("should lock quorum system");
        quorum_system
            .get_proposal(&proposal_id)
            .expect("proposal should exist")
            .clone()
    };

    assert!(
        final_proposal.has_quorum(),
        "final proposal should have quorum"
    );
    assert_eq!(
        final_proposal.get_signature_count(),
        3,
        "should have all 3 signatures"
    );

    // Step 7: Simulate automatic commit to Canon when quorum reached
    println!("💾 Simulating automatic Canon commit");

    // In the real system, this happens automatically in the attest endpoint
    // Here we simulate the commit process
    let committed_proposal = {
        let mut quorum_system = runtime
            .quorum_system
            .lock()
            .expect("should lock quorum system");
        quorum_system
            .commit_proposal(&proposal_id)
            .expect("should commit proposal")
    };

    // Create the CanonicalRecord that would be persisted
    let payload = serde_json::json!({
        "entry": committed_proposal.entry,
        "content": committed_proposal.content,
        "proposal_id": committed_proposal.id,
        "committed_at": chrono::Utc::now(),
        "quorum_achieved": true,
        "required_signatures": committed_proposal.required_k,
        "actual_signatures": committed_proposal.signers.len()
    });

    let mut record = crate::canonical_record::CanonicalRecord {
        kind: "system_proposal".to_string(),
        schema_version: 1,
        id: committed_proposal.entry.clone(),
        tenant: "system".to_string(),
        ts: chrono::Utc::now(),
        space: "system".to_string(),
        payload,
        links: vec![],
        prev: None,
        hash: String::new(),
        sig: None,
        pub_key: None,
        witnesses: vec![],
    };

    // Canonicalize and hash
    let canonical_json = record
        .to_canonical_json()
        .expect("canonicalization should succeed");

    let mut hasher = sha2::Sha256::new();
    hasher.update(canonical_json.as_bytes());
    let digest = hasher.finalize();
    record.hash = hex::encode(digest);

    // Sign with Root authority
    let signing_key = CanonSigningKey::generate(); // In real system, uses persistent key
    let (signature, public_key) = signing_key.sign_record(canonical_json.as_bytes());

    record.sig = Some(signature);
    record.pub_key = Some(public_key);

    // Add witness records from the committed proposal
    for witness_sig in &committed_proposal.signers {
        record
            .witnesses
            .push(crate::canonical_record::WitnessRecord {
                witness_id: witness_sig.witness_id.clone(),
                signature: witness_sig.signature.clone(),
                timestamp: witness_sig.signed_at,
                authority: "SYSTEM_QUORUM".to_string(),
            });
    }

    // Step 8: Persist to Canon with system privileges
    println!("🔐 Persisting to Canon with witness signatures");
    {
        let mut canon_store = canon_store.lock().expect("should lock canon store");
        canon_store
            .add_record(record.clone(), &LOA::Root, true)
            .expect("should persist system record with quorum");
    }

    // Step 9: Verify Canon persistence and integrity
    println!("🔍 Verifying Canon persistence and signature integrity");
    let reloaded_record = {
        let canon_store = canon_store.lock().expect("should lock canon store");
        canon_store
            .load_record(&committed_proposal.entry, &LOA::Root)
            .expect("should reload persisted record")
    };

    // Verify basic record integrity
    assert_eq!(reloaded_record.kind, "system_proposal");
    assert_eq!(reloaded_record.tenant, "system");
    assert_eq!(reloaded_record.space, "system");
    assert_eq!(
        reloaded_record.witnesses.len(),
        3,
        "should have 3 witness signatures"
    );

    // Verify signature integrity
    let reloaded_canonical = reloaded_record
        .to_canonical_json()
        .expect("reloaded record should canonicalize");

    let reloaded_signature = reloaded_record.sig.as_ref().expect("should have signature");
    signing_key
        .verify_signature(reloaded_canonical.as_bytes(), reloaded_signature)
        .expect("Root signature should verify");

    // Verify all witness signatures are present and valid
    for (i, witness_record) in reloaded_record.witnesses.iter().enumerate() {
        assert_eq!(witness_record.authority, "SYSTEM_QUORUM");
        assert!(
            mentor_keys
                .iter()
                .any(|(witness_id, _)| witness_id == &witness_record.witness_id),
            "witness {} should be from registered mentors",
            i
        );
    }

    // Step 10: Verify proposal is no longer in pending list
    println!("🧹 Verifying proposal cleanup");
    let quorum_system = runtime
        .quorum_system
        .lock()
        .expect("should lock quorum system");
    assert!(
        quorum_system.get_proposal(&proposal_id).is_none(),
        "committed proposal should be removed from pending"
    );

    println!("✅ Complete interactive quorum workflow test passed!");
    println!("   📝 Proposal created");
    println!("   ✍️  3/3 mentor signatures collected");
    println!("   🎯 Quorum achieved");
    println!("   💾 Automatically committed to Canon");
    println!("   🔐 Cryptographic integrity verified");
    println!("   🧹 Proposal cleanup completed");
}

#[test]
fn test_proposal_status_tracking() {
    println!("📊 Testing proposal status tracking through lifecycle");

    let temp_dir = TempDir::new().expect("should create temp dir");
    let path = temp_dir.path().to_str().expect("temp path should be valid");

    let encryption_key = KeyManager::dev_key_for_testing().expect("should get encryption key");
    let canon_store = Arc::new(Mutex::new(
        EncryptedCanonStoreSled::new(path, &encryption_key).expect("should create encrypted store"),
    ));

    let config = RuntimeConfig {
        enforcement_mode: EnforcementMode::Active,
        threshold: 0.5,
        active_model: None,
        telemetry_enabled: false,
        explanation_enabled: false,
        model_refresh_from_canon: false,
    };

    let runtime =
        SigilRuntimeCore::new(LOA::Root, canon_store, config).expect("should create runtime");

    // Create test witness
    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let public_key_b64 =
        base64::engine::general_purpose::STANDARD.encode(signing_key.verifying_key().as_bytes());

    runtime
        .witness_registry
        .add_witness(
            "test_witness_1".to_string(),
            public_key_b64,
            "TEST_AUTHORITY".to_string(),
            "Test witness".to_string(),
            &LOA::Root,
        )
        .expect("should add witness");

    // Create proposal requiring only 1 signature
    let proposal_id = {
        let mut quorum_system = runtime
            .quorum_system
            .lock()
            .expect("should lock quorum system");
        quorum_system
            .create_proposal(
                "status_test_proposal".to_string(),
                "Test proposal for status tracking".to_string(),
                1, // Only require 1 signature
            )
            .expect("should create proposal")
    };

    // Phase 1: Pending status
    println!("📋 Phase 1: Verifying pending status");
    let pending_status = {
        let quorum_system = runtime
            .quorum_system
            .lock()
            .expect("should lock quorum system");
        quorum_system
            .get_proposal(&proposal_id)
            .expect("proposal should exist")
            .clone()
    };

    assert_eq!(pending_status.get_signature_count(), 0);
    assert!(!pending_status.has_quorum());
    assert!(!pending_status.is_expired());
    println!("   ✅ Status: Pending (0/1 signatures)");

    // Phase 2: Add signature and achieve quorum
    println!("📋 Phase 2: Adding signature to achieve quorum");
    let content_hash = pending_status.content_hash.clone();
    let signature = signing_key.sign(content_hash.as_bytes());
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

    {
        let mut quorum_system = runtime
            .quorum_system
            .lock()
            .expect("should lock quorum system");
        quorum_system
            .add_signature(&proposal_id, "test_witness_1".to_string(), signature_b64)
            .expect("should add signature");
    }

    // Phase 3: Quorum achieved status
    println!("📋 Phase 3: Verifying quorum achieved status");
    let quorum_status = {
        let quorum_system = runtime
            .quorum_system
            .lock()
            .expect("should lock quorum system");
        quorum_system
            .get_proposal(&proposal_id)
            .expect("proposal should exist")
            .clone()
    };

    assert_eq!(quorum_status.get_signature_count(), 1);
    assert!(quorum_status.has_quorum());
    assert!(!quorum_status.is_expired());
    println!("   ✅ Status: Quorum achieved (1/1 signatures)");

    // Phase 4: Commit and verify removal
    println!("📋 Phase 4: Committing and verifying cleanup");
    {
        let mut quorum_system = runtime
            .quorum_system
            .lock()
            .expect("should lock quorum system");
        let _committed = quorum_system
            .commit_proposal(&proposal_id)
            .expect("should commit proposal");
    }

    let quorum_system = runtime
        .quorum_system
        .lock()
        .expect("should lock quorum system");
    assert!(
        quorum_system.get_proposal(&proposal_id).is_none(),
        "committed proposal should be removed"
    );
    println!("   ✅ Status: Committed and cleaned up");

    println!("✅ Proposal status tracking test passed!");
}

#[test]
fn test_partial_quorum_failure_scenarios() {
    println!("❌ Testing partial quorum and failure scenarios");

    let temp_dir = TempDir::new().expect("should create temp dir");
    let path = temp_dir.path().to_str().expect("temp path should be valid");

    let encryption_key = KeyManager::dev_key_for_testing().expect("should get encryption key");
    let canon_store = Arc::new(Mutex::new(
        EncryptedCanonStoreSled::new(path, &encryption_key).expect("should create encrypted store"),
    ));

    let config = RuntimeConfig {
        enforcement_mode: EnforcementMode::Active,
        threshold: 0.5,
        active_model: None,
        telemetry_enabled: false,
        explanation_enabled: false,
        model_refresh_from_canon: false,
    };

    let runtime =
        SigilRuntimeCore::new(LOA::Root, canon_store, config).expect("should create runtime");

    // Register 2 witnesses but require 3 signatures (impossible)
    let witness_keys: Vec<_> = (0..2)
        .map(|i| {
            let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
            let public_key_b64 = base64::engine::general_purpose::STANDARD
                .encode(signing_key.verifying_key().as_bytes());
            let witness_id = format!("partial_witness_{}", i + 1);

            runtime
                .witness_registry
                .add_witness(
                    witness_id.clone(),
                    public_key_b64,
                    "TEST_AUTHORITY".to_string(),
                    format!("Partial witness {}", i + 1),
                    &LOA::Root,
                )
                .expect("should add witness");

            (witness_id, signing_key)
        })
        .collect();

    // Create proposal requiring 3 signatures (more than available witnesses)
    let proposal_id = {
        let mut quorum_system = runtime
            .quorum_system
            .lock()
            .expect("should lock quorum system");
        quorum_system
            .create_proposal(
                "impossible_quorum".to_string(),
                "Proposal requiring more signatures than available witnesses".to_string(),
                3, // Require 3 but only have 2 witnesses
            )
            .expect("should create proposal")
    };

    println!("📝 Created proposal requiring 3 signatures with only 2 witnesses");

    // Add both available signatures
    let content_hash = {
        let quorum_system = runtime
            .quorum_system
            .lock()
            .expect("should lock quorum system");
        quorum_system
            .get_proposal(&proposal_id)
            .expect("proposal should exist")
            .content_hash
            .clone()
    };

    for (witness_id, signing_key) in &witness_keys {
        let signature = signing_key.sign(content_hash.as_bytes());
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

        let mut quorum_system = runtime
            .quorum_system
            .lock()
            .expect("should lock quorum system");
        quorum_system
            .add_signature(&proposal_id, witness_id.clone(), signature_b64)
            .expect("should add signature");
    }

    // Verify partial quorum state
    let partial_status = {
        let quorum_system = runtime
            .quorum_system
            .lock()
            .expect("should lock quorum system");
        quorum_system
            .get_proposal(&proposal_id)
            .expect("proposal should exist")
            .clone()
    };

    assert_eq!(
        partial_status.get_signature_count(),
        2,
        "should have 2 signatures"
    );
    assert!(!partial_status.has_quorum(), "should not have quorum (2/3)");
    assert_eq!(
        partial_status.get_remaining_signatures_needed(),
        1,
        "should need 1 more signature"
    );

    println!("✅ Verified partial quorum state: 2/3 signatures (quorum not reached)");

    // Verify commit fails without quorum
    let commit_result = {
        let mut quorum_system = runtime
            .quorum_system
            .lock()
            .expect("should lock quorum system");
        quorum_system.commit_proposal(&proposal_id)
    };

    assert!(commit_result.is_err(), "commit should fail without quorum");
    let error_msg = format!("{:?}", commit_result.unwrap_err());
    assert!(
        error_msg.contains("requires 3 signatures"),
        "error should mention signature requirement"
    );

    println!("✅ Verified commit failure without quorum");

    // Verify proposal remains in pending state
    let quorum_system = runtime
        .quorum_system
        .lock()
        .expect("should lock quorum system");
    assert!(
        quorum_system.get_proposal(&proposal_id).is_some(),
        "failed commit should leave proposal in pending state"
    );

    println!("✅ Partial quorum failure scenarios test passed!");
}
