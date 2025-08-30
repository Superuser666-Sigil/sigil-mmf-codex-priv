use mmf_sigil::irl_runtime::TrustGuard;

#[test]
fn trustguard_allows_benign_input() {
    let info = TrustGuard::score_action("greeting", "say hello");
    assert!(info.score >= 0.5);
    assert!(info.allowed);
    assert_eq!(info.model_id, "rule_based_v1");
}

#[test]
fn trustguard_denies_risky_input() {
    let info = TrustGuard::score_action("malicious", "attempt to hack server");
    assert!(info.score < 0.5);
    assert!(!info.allowed);
    assert_eq!(info.model_id, "rule_based_v1");
}
