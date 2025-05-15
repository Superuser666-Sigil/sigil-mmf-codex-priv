// Canon-Compliant irl_modes.rs
// Purpose: Define and apply runtime trust enforcement modes for MMF + Sigil

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IRLMode {
    Strict,
    Lenient,
    AuditOnly,
}

impl IRLMode {
    pub fn apply(&self, base_score: f32) -> f32 {
        match self {
            IRLMode::Strict => base_score, // no changes
            IRLMode::Lenient => (base_score + 1.0).min(1.0), // boost trust score slightly
            IRLMode::AuditOnly => 1.0, // always assume success
        }
    }

    pub fn should_enforce(&self) -> bool {
        !matches!(self, IRLMode::AuditOnly)
    }
}
