use crate::audit_chain::ReasoningChain;
use crate::irl_reward::RewardModel;
use std::collections::HashMap;
use std::fmt;

pub fn explain_score(chain: &ReasoningChain, score: f32) -> String {
    format!(
        "Based on {} reasoning tokens and {} context tokens, the score {:.2} reflects moderate trust.",
        chain.reasoning.len(),
        chain.context.len(),
        score
    )
}

#[derive(Debug, Clone)]
pub struct MultiModelExplainer {
    pub model_count: usize,
    models: HashMap<String, RewardModel>,
    thresholds: HashMap<String, f64>,
}

impl Default for MultiModelExplainer {
    fn default() -> Self {
        Self::new()
    }
}

impl MultiModelExplainer {
    pub fn new() -> Self {
        MultiModelExplainer { 
            model_count: 1,
            models: HashMap::new(),
            thresholds: HashMap::new(),
        }
    }

    pub fn add_model(&mut self, model: RewardModel, threshold: f64) {
        let model_id = model.model_id.clone();
        self.models.insert(model_id.clone(), model);
        self.thresholds.insert(model_id, threshold);
        self.model_count = self.models.len();
    }

    pub fn explain_event(&self, event: &crate::audit::AuditEvent) -> TrustExplanation {
        let mut explanation = format!(
            "Event '{}' by '{}' on target '{}'",
            event.action,
            event.who,
            event.target.as_deref().unwrap_or("unknown")
        );
        
        // Add LOA-based explanation
        explanation.push_str(&format!("\nLOA Level: {:?}", event.loa));
        
        // Add severity-based explanation
        match event.severity {
            crate::audit::LogLevel::Info => explanation.push_str("\nSeverity: Info"),
            crate::audit::LogLevel::Warn => explanation.push_str("\nSeverity: Warning"),
            crate::audit::LogLevel::Error => explanation.push_str("\nSeverity: Error"),
            crate::audit::LogLevel::Critical => explanation.push_str("\nSeverity: Critical"),
        }
        
        // Calculate confidence based on available models
        let confidence = if self.model_count > 0 {
            0.5 + (self.model_count as f32 * 0.1).min(0.4)
        } else {
            0.3
        };
        
        TrustExplanation::new(&explanation, confidence)
    }
    
    pub fn explain_chain(&self, chain: &ReasoningChain) -> TrustExplanation {
        let mut explanation = format!(
            "Reasoning chain with {} reasoning steps and {} context tokens",
            chain.reasoning.len(),
            chain.context.len()
        );
        
        // Add verdict explanation
        explanation.push_str(&format!("\nVerdict: {:?}", chain.verdict));
        
        // Add IRL score explanation
        explanation.push_str(&format!("\nIRL Trust Score: {:.2}", chain.irl.score));
        
        // Add model-based confidence
        let confidence = if self.model_count > 0 {
            chain.irl.score * 0.8 + (self.model_count as f32 * 0.05).min(0.2)
        } else {
            chain.irl.score * 0.6
        };
        
        TrustExplanation::new(&explanation, confidence)
    }
}

#[derive(Debug, Clone)]
pub struct TrustExplanation {
    pub explanation: String,
    pub confidence: f32,
}

impl TrustExplanation {
    pub fn new(explanation: &str, confidence: f32) -> Self {
        TrustExplanation {
            explanation: explanation.to_string(),
            confidence: confidence.clamp(0.0, 1.0),
        }
    }
}

impl fmt::Display for TrustExplanation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Explanation: {}\nConfidence: {:.2}", self.explanation, self.confidence)
    }
}