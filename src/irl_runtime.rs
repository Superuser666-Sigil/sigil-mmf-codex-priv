use crate::audit_chain::IRLInfo;

/// TrustGuard is responsible for scoring runtime actions using IRL-derived policies.
/// Under Rule Zero, it must emit a transparent trust score and justification for every decision.
pub struct TrustGuard;

impl TrustGuard {
    /// Scores an action or suggestion in terms of trustworthiness.
    /// For now, returns a fixed placeholder score.
    pub fn score_action(_context: &str, _input: &str) -> IRLInfo {
        // Future: plug into trained policy model and feature extractors
        IRLInfo {
            model_id: "sigil_trust_v1".to_string(),
            score: 0.0, // Default to zero until real model is integrated
            allowed: false,
        }
    }
}
