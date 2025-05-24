// Canon-Compliant irl_explainer.rs
// Purpose: Provide transparent explanation traces for IRL decisions within MMF + Sigil

use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use crate::audit::{AuditEvent, LogLevel};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExplanationTrace {
    pub trace_id: String,
    pub action: String,
    pub input_features: Vec<String>,
    pub weighted_factors: Vec<(String, f32)>,
    pub irl_score: f32,
    pub outcome: String,
    pub audit: AuditEvent,
    pub timestamp: DateTime<Utc>,
}

/// Generates an explanation trace for an IRL decision, including the weighted influence of feature factors.
pub fn explain_decision(
    trace_id: &str,
    action: &str,
    input_features: Vec<String>,
    weights: Vec<(String, f32)>,
    irl_score: f32,
    outcome: &str,
    source: &str,
) -> ExplanationTrace {
    let audit = AuditEvent::new(
        "system",
        action,
        trace_id,
        source,
    )
    .with_severity(LogLevel::Debug)
    .with_context(format!("Explaining IRL decision for action '{}', outcome '{}'", action, outcome));

    ExplanationTrace {
        trace_id: trace_id.into(),
        action: action.into(),
        input_features,
        weighted_factors: weights,
        irl_score,
        outcome: outcome.into(),
        audit,
        timestamp: Utc::now(),
    }
}

/// Placeholder: future runtime registry of explanation traces for debugging or export
pub fn trace_summary(trace: &ExplanationTrace) -> String {
    format!(
        "[{}] Action: {}, Outcome: {}, IRL Score: {:.2}",
        trace.timestamp,
        trace.action,
        trace.outcome,
        trace.irl_score
    )
}

/// Placeholder: hook for exporting or logging traces to disk, telemetry sink, or memory vault
pub fn export_trace(_trace: &ExplanationTrace) -> Result<(), String> {
    // TODO: persist ExplanationTrace to log or vault-compatible target
    Ok(())
}
