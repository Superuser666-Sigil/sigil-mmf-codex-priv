use crate::audit_chain::IRLInfo;
use crate::trust_linear::{TrustFeatures, TrustLinearModel};
use crate::loa::LOA;

/// TrustGuard is responsible for scoring runtime actions using IRL-derived policies.
/// Under Rule Zero, it must emit a transparent trust score and justification for every decision.
pub struct TrustGuard;

impl TrustGuard {
    /// Scores an action or suggestion in terms of trustworthiness using
    /// the logistic trust model. The returned [`IRLInfo`] includes the
    /// model identifier, a dynamic score, and the `allowed` decision so the
    /// evaluation can be audited later.
    pub fn score_action(context: &str, input: &str) -> IRLInfo {
        // Use the logistic trust model instead of keyword-based policy
        let model = TrustLinearModel::new_default();
        let features = TrustFeatures::new(
            input, // action
            Some(context), // target
            &LOA::Observer, // default LOA
            0, // recent requests
            input, // input for entropy
        );
        
        let (score, allowed) = model.evaluate(&features);
        let model_id = "trust_linear_v1".to_string();
        
        // Emit an audit-friendly trace of the decision path.
        println!(
            "TrustGuard::score_action model={model_id} score={score:.4} allowed={allowed}"
        );
        IRLInfo {
            model_id,
            score: score as f32,
            allowed,
        }
    }
}
