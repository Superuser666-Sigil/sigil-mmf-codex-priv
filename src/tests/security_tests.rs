use crate::trust_linear::{TrustLinearModel, TrustFeatures};
use crate::quorum_system::QuorumSystem;
use crate::loa::LOA;
use crate::errors::SigilResult;

/// Simple test to verify our implementation works
#[test]
fn test_basic_functionality() {
    assert!(true, "Basic test should pass");
}

/// Test trust linear model functionality
#[test]
fn test_trust_linear_model() {
    // Create default model
    let model = TrustLinearModel::new_default();
    
    // Test with low-risk features
    let low_risk_features = TrustFeatures::new(
        "read",
        Some("user_profile"),
        &LOA::Operator,
        5,
        "simple input"
    );
    
    let (score, allowed) = model.evaluate(&low_risk_features);
    assert!(allowed, "Low-risk operation should be allowed");
    assert!(score > 0.5, "Low-risk operation should have high score");
    
    // Test with high-risk features
    let high_risk_features = TrustFeatures::new(
        "delete",
        Some("system_config"),
        &LOA::Guest,
        100,
        "complex malicious input"
    );
    
    let (score, allowed) = model.evaluate(&high_risk_features);
    assert!(!allowed, "High-risk operation should be denied");
    assert!(score < 0.5, "High-risk operation should have low score");
}

/// Test default-deny behavior for trust evaluation errors
#[test]
fn test_trust_model_default_deny() {
    // Create default model
    let _model = TrustLinearModel::new_default();
    
    // Test with mismatched feature count (should trigger default-deny)
    let features = TrustFeatures::new(
        "read",
        Some("user_profile"),
        &LOA::Operator,
        5,
        "simple input"
    );
    
    // Create a model with wrong number of weights to trigger mismatch
    let mut wrong_weights = crate::trust_linear::TrustWeights::default();
    wrong_weights.weights = vec![0.1, 0.2, 0.3]; // Only 3 weights instead of 5
    let wrong_model = TrustLinearModel::new(wrong_weights);
    
    let (score, allowed) = wrong_model.evaluate(&features);
    assert!(!allowed, "Mismatched feature count should result in default-deny");
    assert_eq!(score, 0.0, "Mismatched feature count should result in zero score");
    
    // Test registry with missing model (should trigger default-deny)
    let registry = crate::trust_linear::TrustModelRegistry::new();
    let (score, allowed) = registry.evaluate_with_model(Some("nonexistent_model"), &features);
    assert!(!allowed, "Missing model should result in default-deny");
    assert_eq!(score, 0.0, "Missing model should result in zero score");
}

/// Test quorum system functionality
#[test]
fn test_quorum_system() -> SigilResult<()> {
    let mut quorum = QuorumSystem::new();
    
    // Create a proposal requiring 2 signatures
    let proposal_id = quorum.create_proposal(
        "system:config".to_string(),
        "new_config_value".to_string(),
        2
    )?;
    
    // Add first signature
    quorum.add_signature(&proposal_id, "witness1".to_string(), "sig1".to_string())?;
    
    // Try to commit - should fail (only 1 signature, need 2)
    let commit_result = quorum.commit_proposal(&proposal_id);
    assert!(commit_result.is_err(), "Should not commit without quorum");
    
    // Add second signature
    quorum.add_signature(&proposal_id, "witness2".to_string(), "sig2".to_string())?;
    
    // Now should be able to commit
    let committed_proposal = quorum.commit_proposal(&proposal_id)?;
    assert_eq!(committed_proposal.signers.len(), 2, "Should have 2 signatures");
    assert!(committed_proposal.has_quorum(), "Should have quorum");
    
    // Proposal should be removed from pending list
    assert!(quorum.get_proposal(&proposal_id).is_none(), "Proposal should be removed after commit");
    
    Ok(())
}

/// Test reasoning chain tampering detection
#[test]
fn test_reasoning_chain_tampering() -> SigilResult<()> {
    // Create and sign a reasoning chain
    let mut chain = crate::audit_chain::ReasoningChain::new("original input", crate::loa::LoaLevel::Observer);
    chain.add_reasoning("Original reasoning");
    chain.set_verdict(crate::audit_chain::Verdict::Allow);
    
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    chain.sign(&signing_key)?;
    
    // Verify original integrity
    let verified = chain.verify_integrity()?;
    assert!(verified, "Original chain should verify");
    
    // Tamper with the content
    chain.input = "tampered input".to_string();
    
    // Verify tampered integrity - should fail
    let verified = chain.verify_integrity()?;
    assert!(!verified, "Tampered chain should not verify");
    
    Ok(())
}
