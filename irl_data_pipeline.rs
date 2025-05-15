// Canon-Compliant irl_data_pipeline.rs
// Purpose: Ingest and persist ExplanationTraces and audit telemetry for IRL training and validation

use chrono::Utc;
use serde::{Deserialize, Serialize};
use crate::audit::{AuditEvent, LogLevel};
use crate::irl_explainer::ExplanationTrace;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IngestResult {
    pub accepted: bool,
    pub message: String,
    pub trace_id: String,
    pub irl_score: f32,
    pub audit: AuditEvent,
    pub timestamp: chrono::DateTime<Utc>,
}

/// Ingests a single ExplanationTrace into the pipeline (e.g., vault, disk, buffer).
/// Returns a telemetry-safe IngestResult with audit trace.
pub fn ingest_trace(trace: &ExplanationTrace) -> IngestResult {
    let accepted = trace.irl_score >= 0.0; // Accept everything unless explicitly blocked

    let audit = AuditEvent::new(
        "system",
        "irl_data_pipeline",
        &trace.trace_id,
        "irl_data_pipeline.rs",
    )
    .with_severity(if accepted { LogLevel::Info } else { LogLevel::Warn })
    .with_context(format!("Ingested trace for action '{}' with score {:.2}", trace.action, trace.irl_score));

    // TODO: Persist trace to vault, telemetry buffer, or append-only log

    IngestResult {
        accepted,
        message: if accepted {
            "Trace accepted for telemetry/training".into()
        } else {
            "Trace rejected (score < 0.0)".into()
        },
        trace_id: trace.trace_id.clone(),
        irl_score: trace.irl_score,
        audit,
        timestamp: Utc::now(),
    }
}

/// Future hook: batch ingestion
pub fn ingest_batch(batch: &[ExplanationTrace]) -> Vec<IngestResult> {
    batch.iter().map(ingest_trace).collect()
}