/// A simple policy model used by TrustGuard.
/// In a production system this would call a trained model loaded from the
/// `models/` directory. For this example we use lightweight keyword checks
/// to produce a deterministic trust score.
///
/// The returned tuple contains `(model_id, score, allowed)` where:
/// - `model_id` identifies the policy or model used for scoring.
/// - `score` is a floating point trust score between 0.0 and 1.0.
/// - `allowed` is derived from the score and indicates if the action is
///   considered trustworthy.
pub struct PolicyModel;

impl PolicyModel {
    /// Evaluates the provided context and input and produces a trust score
    /// along with a boolean decision. The logic here is intentionally simple
    /// so that it can be audited easily.
    pub fn evaluate(context: &str, input: &str) -> (String, f32, bool) {
        let combined = format!("{} {}", context, input).to_lowercase();
        // Basic keyword based policy for demonstration purposes.
        let score = if combined.contains("hack") || combined.contains("deny") {
            0.0
        } else if combined.contains("allow") || combined.contains("hello") {
            0.9
        } else {
            0.5
        };

        let allowed = score >= 0.5;
        ("rule_based_v1".to_string(), score, allowed)
    }
}
