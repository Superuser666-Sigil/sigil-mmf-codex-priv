use crate::loa::LOA;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// TrustWeights configuration for the linear trust model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustWeights {
    pub bias: f64,
    pub weights: Vec<f64>,
    pub threshold: f64,
}

impl Default for TrustWeights {
    fn default() -> Self {
        Self {
            bias: -0.8, // Balanced restrictive bias for security
            weights: vec![0.15, 0.15, 0.4, 0.15, 0.15], // LOA gets double weight for privilege enforcement
            threshold: 0.4, // Security threshold - Allow Operator+ for modules, deny Guest risky actions
        }
    }
}

/// Feature vector for trust evaluation
#[derive(Debug, Clone)]
pub struct TrustFeatures {
    pub action_class: f64,      // 0.0-1.0 risk level of action type
    pub target_class: f64,      // 0.0-1.0 sensitivity of target
    pub loa_level: f64,         // 0.0-1.0 normalized LOA level
    pub rate_limit_recent: f64, // 0.0-1.0 recent request frequency
    pub input_entropy: f64,     // 0.0-1.0 entropy/complexity of input
}

impl TrustFeatures {
    pub fn new(action: &str, target: Option<&str>, loa: &LOA, recent_requests: usize, input: &str) -> Self {
        // Action class risk scoring
        let action_class = match action.to_lowercase().as_str() {
            "read" | "get" | "query" | "canon_read" | "audit_read" | "config_read" => 0.1,
            "write" | "update" | "modify" | "canon_write" | "config_write" => 0.6,
            "delete" | "remove" => 0.9,
            "execute" | "run" | "module_execute" => 0.4, // Module execution is lower risk for authenticated users
            "admin" | "system" => 0.95,
            "trust_check" => 0.1, // Trust checks are low risk queries
            "elevation_request" => 0.8, // LOA elevation is high risk
            _ => 0.5,
        };

        // Target class sensitivity scoring
        let target_class = match target {
            Some(t) => match t.to_lowercase().as_str() {
                "user" | "profile" => 0.3,
                "canon" | "system" => 0.9,
                "audit" | "log" => 0.8,
                "config" | "settings" => 0.7,
                "hello" | "module" => 0.2, // Built-in modules are low risk
                _ => 0.5,
            },
            None => 0.5,
        };

        // LOA level normalization (0.0-1.0)
        let loa_level = match loa {
            LOA::Guest => 0.0,
            LOA::Observer => 0.4,
            LOA::Operator => 0.6,
            LOA::Mentor => 0.8,
            LOA::Root => 1.0,
        };

        // Rate limit scoring (normalize recent requests)
        let rate_limit_recent = (recent_requests as f64 / 100.0).min(1.0);

        // Input entropy scoring (simple complexity measure)
        let input_entropy = {
            let unique_chars = input.chars().collect::<std::collections::HashSet<_>>().len();
            let length = input.len();
            if length == 0 {
                0.0
            } else {
                (unique_chars as f64 / length as f64).min(1.0)
            }
        };

        Self {
            action_class,
            target_class,
            loa_level,
            rate_limit_recent,
            input_entropy,
        }
    }

    pub fn to_vector(&self) -> Vec<f64> {
        vec![
            self.action_class,
            self.target_class,
            self.loa_level,
            self.rate_limit_recent,
            self.input_entropy,
        ]
    }
}

/// Linear trust model with logistic scoring
pub struct TrustLinearModel {
    weights: TrustWeights,
}

impl TrustLinearModel {
    pub fn new(weights: TrustWeights) -> Self {
        Self { weights }
    }

    pub fn new_default() -> Self {
        Self::new(TrustWeights::default())
    }

    /// Evaluate trust using logistic regression
    pub fn evaluate(&self, features: &TrustFeatures) -> (f64, bool) {
        let feature_vec = features.to_vector();
        
        // Ensure we have the right number of features
        if feature_vec.len() != self.weights.weights.len() {
            return (0.0, false); // Default deny on mismatch
        }

        // Linear combination: bias + sum(weight_i * feature_i)
        let linear_score = self.weights.bias + 
            feature_vec.iter()
                .zip(self.weights.weights.iter())
                .map(|(f, w)| f * w)
                .sum::<f64>();

        // Apply logistic function to get probability
        let score = 1.0 / (1.0 + (-linear_score).exp());
        
        // Determine if allowed based on threshold
        let allowed = score >= self.weights.threshold;

        (score, allowed)
    }

    /// Update weights from configuration
    pub fn update_weights(&mut self, weights: TrustWeights) {
        self.weights = weights;
    }

    /// Get current weights
    pub fn get_weights(&self) -> &TrustWeights {
        &self.weights
    }
}

/// Trust model registry for managing multiple models
pub struct TrustModelRegistry {
    models: HashMap<String, TrustLinearModel>,
    default_model: String,
}

impl TrustModelRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            models: HashMap::new(),
            default_model: "trust_linear_v1".to_string(),
        };

        // Register default model
        registry.models.insert(
            registry.default_model.clone(),
            TrustLinearModel::new_default(),
        );

        registry
    }

    pub fn register_model(&mut self, name: &str, model: TrustLinearModel) {
        self.models.insert(name.to_string(), model);
    }

    pub fn get_model(&self, name: Option<&str>) -> Option<&TrustLinearModel> {
        let model_name = name.unwrap_or(&self.default_model);
        self.models.get(model_name)
    }

    pub fn evaluate_with_model(
        &self,
        model_name: Option<&str>,
        features: &TrustFeatures,
    ) -> (f64, bool) {
        match self.get_model(model_name) {
            Some(model) => model.evaluate(features),
            None => (0.0, false), // Default deny if model not found
        }
    }
}

impl Default for TrustModelRegistry {
    fn default() -> Self {
        Self::new()
    }
}
