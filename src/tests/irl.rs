// tests/irl.rs
use mmf_sigil::irl_trust_evaluator::TrustEvaluator;
use mmf_sigil::audit_chain::ReasoningChain;
use mmf_sigil::loa::LOA;
use mmf_sigil::audit::{AuditEvent, LogLevel};
use mmf_sigil::irl_reward::RewardModel;

#[test]
fn test_default_trust_evaluator_scores_chain() {
    let evaluator = TrustEvaluator::new();
    let mut chain = ReasoningChain::new("Test input", LOA::Operator);
    chain.add_reasoning_step("This is a test step.");
    
    let score = evaluator.evaluate(&chain);
    
    // Default model and features should produce a predictable, non-zero score
    assert!(score > 0.0);
    assert!(score <= 1.0);
}

#[test]
fn test_custom_model_and_threshold() {
    let mut evaluator = TrustEvaluator::new();
    let custom_model = RewardModel::new("custom_v1", None, vec![], vec![0.1, 0.2, 0.7]);
    evaluator.add_model(custom_model, 0.8);
    
    // Switch to the custom model
    evaluator.model_id = "custom_v1".to_string();
    
    let mut chain = ReasoningChain::new("Test with custom model", LOA::Root);
    chain.add_reasoning_step("This should be evaluated by the custom model.");
    
    let event = AuditEvent::new("test_event", "test_target", Some("session1"), "test.rs", &LOA::Root);
    
    let (score, allowed) = evaluator.evaluate_event(&event, "custom_v1").unwrap();
    
    // The score should be influenced by the custom weights
    // and since the default features are low, the score should be below the threshold
    assert!(score < 0.8);
    assert!(!allowed);
}

#[test]
fn test_evaluate_event_produces_valid_output() {
    let evaluator = TrustEvaluator::new_with_model("test_model");
    let event = AuditEvent::new(
        "canon_write", 
        Some("protected_node"), 
        Some("session_operator_123"),
        "src/canon_store.rs",
        &LOA::Operator,
    ).with_severity(LogLevel::High);

    let result = evaluator.evaluate_event(&event, "test_model");
    
    assert!(result.is_ok());
    let (score, allowed) = result.unwrap();
    
    assert!(score >= 0.0 && score <= 1.0);
    // Based on the default weights in new_with_model ([0.25, 0.25, 0.5])
    // and a simple chain, the score should be below the default threshold of 0.6
    assert!(!allowed);
}

#[test]
fn test_model_listing_and_counting() {
    let mut evaluator = TrustEvaluator::new();
    assert_eq!(evaluator.get_model_count(), 1);
    assert_eq!(evaluator.list_models(), vec!["default".to_string()]);

    let custom_model = RewardModel::new("custom_v1", None, vec![], vec![]);
    evaluator.add_model(custom_model, 0.5);

    assert_eq!(evaluator.get_model_count(), 2);
    let mut models = evaluator.list_models();
    models.sort(); // Sort for predictable order
    assert_eq!(models, vec!["custom_v1".to_string(), "default".to_string()]);
}
