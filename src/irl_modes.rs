use crate::audit_chain::{ReasoningChain, Verdict};
use crate::audit_store::write_chain;

pub fn get_mode(chain: &mut ReasoningChain) -> &'static str {
    chain.add_context("Checked runtime IRL mode");
    chain.add_reasoning("Trust enforcement currently operates in passive mode only.");
    chain.add_suggestion("Return mode as 'passive'");
    chain.set_verdict(Verdict::Allow);
    chain.set_irl_score(0.0, true);
    let _ = write_chain(chain.clone());
    "passive"
}

// Missing types that are referenced in other modules
#[derive(Debug, Clone)]
pub enum EnforcementMode {
    Passive,
    Active,
    Strict,
}

impl EnforcementMode {
    pub fn is_logging(&self) -> bool {
        matches!(self, EnforcementMode::Active | EnforcementMode::Strict)
    }
}

#[derive(Debug, Clone)]
pub struct IRLModeManager {
    pub current_mode: EnforcementMode,
}

impl Default for IRLModeManager {
    fn default() -> Self {
        Self::new()
    }
}

impl IRLModeManager {
    pub fn new() -> Self {
        IRLModeManager {
            current_mode: EnforcementMode::Passive,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TrustEvaluation {
    pub score: f32,
    pub allowed: bool,
}

impl TrustEvaluation {
    pub fn new(score: f32, allowed: bool) -> Self {
        TrustEvaluation { score, allowed }
    }
}

// Missing type that is referenced in other modules
#[derive(Debug, Clone)]
pub struct IRLConfig {
    pub active_model: Option<String>,
    pub threshold: f64,
    pub enforcement_mode: EnforcementMode,
    pub telemetry_enabled: bool,
    pub explanation_enabled: bool,
}

impl Default for IRLConfig {
    fn default() -> Self {
        IRLConfig {
            active_model: None,
            threshold: 0.5,
            enforcement_mode: EnforcementMode::Passive,
            telemetry_enabled: false,
            explanation_enabled: false,
        }
    }
}