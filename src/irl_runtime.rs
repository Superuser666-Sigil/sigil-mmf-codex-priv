use crate::audit_chain::IRLInfo;
use crate::policy_model::PolicyModel;

/// TrustGuard is responsible for scoring runtime actions using IRL-derived policies.
/// Under Rule Zero, it must emit a transparent trust score and justification for every decision.
pub struct TrustGuard;

impl TrustGuard {
    /// Scores an action or suggestion in terms of trustworthiness by
    /// delegating to a policy model. The returned [`IRLInfo`] includes the
    /// model identifier, a dynamic score, and the `allowed` decision so the
    /// evaluation can be audited later.
    pub fn score_action(context: &str, input: &str) -> IRLInfo {
        let (model_id, score, allowed) = PolicyModel::evaluate(context, input);
        // Emit an audit-friendly trace of the decision path.
        println!(
            "TrustGuard::score_action model={model_id} score={score:.2} allowed={allowed}"
        );
        IRLInfo {
            model_id,
            score,
            allowed,
        }
    }
}
