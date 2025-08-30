use crate::audit_chain::ReasoningChain;
use crate::irl_feature_store::vectorize_chain;
use crate::irl_reward::RewardModel;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct TrustEvaluator {
    pub model_id: String,
    models: HashMap<String, RewardModel>,
    thresholds: HashMap<String, f64>,
    fallback_model: RewardModel,
}

impl Default for TrustEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustEvaluator {
    pub fn new() -> Self {
        let mut evaluator = TrustEvaluator {
            model_id: "default".to_string(),
            models: HashMap::new(),
            thresholds: HashMap::new(),
            fallback_model: RewardModel::new("fallback", None, vec![], vec![0.33, 0.33, 0.34]),
        };

        // Add default model
        let default_model = RewardModel::new("default", None, vec![], vec![0.3, 0.3, 0.4]);
        evaluator.add_model(default_model, 0.5);

        evaluator
    }

    pub fn new_with_model(model_id: &str) -> Self {
        let mut evaluator = TrustEvaluator {
            model_id: model_id.to_string(),
            models: HashMap::new(),
            thresholds: HashMap::new(),
            fallback_model: RewardModel::new("fallback", None, vec![], vec![0.33, 0.33, 0.34]),
        };

        // Add specified model with default weights
        let model = RewardModel::new(model_id, None, vec![], vec![0.25, 0.25, 0.5]);
        evaluator.add_model(model, 0.6);

        evaluator
    }

    pub fn evaluate(&self, chain: &ReasoningChain) -> f32 {
        // Extract features from the reasoning chain
        let features = match vectorize_chain(chain) {
            Ok(features) => features,
            Err(_) => return 0.0, // Return 0 trust if feature extraction fails
        };

        // Get the active model
        let model = self.models.get(&self.model_id).unwrap_or_else(|| {
            // Fallback to default model if active model not found
            self.models.get("default").unwrap_or(&self.fallback_model)
        });

        // Calculate weighted score
        let score = features
            .iter()
            .zip(model.weights.iter())
            .map(|(feature, weight)| feature * weight)
            .sum::<f32>();

        // Normalize to 0-1 range
        score.clamp(0.0, 1.0)
    }

    pub fn add_model(&mut self, model: RewardModel, threshold: f64) {
        let model_id = model.model_id.clone();
        self.models.insert(model_id.clone(), model);
        self.thresholds.insert(model_id, threshold);
    }

    pub fn evaluate_event(
        &self,
        event: &crate::audit::AuditEvent,
        model_id: &str,
    ) -> Result<(f32, bool), String> {
        // Create a simple reasoning chain from the audit event
        let mut chain = ReasoningChain::new(
            format!(
                "Event: {} on {}",
                event.action,
                event.target.as_deref().unwrap_or("unknown")
            ),
            event.loa.clone(),
        );

        chain.add_context(format!("Event by {} at {}", event.who, event.timestamp));
        chain.add_reasoning_step("Evaluating trust based on event characteristics");

        let threshold = self.thresholds.get(model_id).unwrap_or(&0.5);

        // Calculate trust score
        let score = self.evaluate(&chain);
        let allowed = score >= *threshold as f32;

        chain.set_verdict(if allowed {
            crate::audit_chain::Verdict::Allow
        } else {
            crate::audit_chain::Verdict::Deny
        });
        chain.set_irl_score(score, allowed);

        Ok((score, allowed))
    }

    pub fn get_model_count(&self) -> usize {
        self.models.len()
    }

    pub fn list_models(&self) -> Vec<String> {
        self.models.keys().cloned().collect()
    }
}
