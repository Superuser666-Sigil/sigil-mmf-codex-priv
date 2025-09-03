// Runtime configuration types for Sigil MVP
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
pub struct TrustEvaluation {
    pub score: f32,
    pub allowed: bool,
}

impl TrustEvaluation {
    pub fn new(score: f32, allowed: bool) -> Self {
        TrustEvaluation { score, allowed }
    }
}

/// Runtime configuration for Sigil MVP
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub threshold: f64,
    pub enforcement_mode: EnforcementMode,
    pub telemetry_enabled: bool,
    // Legacy fields kept for backwards compatibility during transition
    pub active_model: Option<String>,
    pub explanation_enabled: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        RuntimeConfig {
            threshold: 0.5,
            enforcement_mode: EnforcementMode::Active,
            telemetry_enabled: false,
            active_model: None,
            explanation_enabled: false,
        }
    }
}


