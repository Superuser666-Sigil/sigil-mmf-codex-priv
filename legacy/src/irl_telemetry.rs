use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::Path;

use crate::audit_chain::ReasoningChain;

pub fn log_telemetry(chain: &ReasoningChain) -> std::io::Result<()> {
    let telemetry = IRLTelemetry::from_chain(chain);
    telemetry.write_to_file("logs/telemetry.jsonl")?;
    println!(
        "[TELEMETRY] Logged chain with {} reasoning tokens",
        chain.reasoning.len()
    );
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IRLTelemetry {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub data: String,
    pub chain_id: String,
    pub reasoning_tokens: usize,
    pub context_tokens: usize,
    pub trust_score: f32,
    pub verdict: String,
}

impl IRLTelemetry {
    pub fn new(event_type: &str, data: &str) -> Self {
        IRLTelemetry {
            timestamp: Utc::now(),
            event_type: event_type.to_string(),
            data: data.to_string(),
            chain_id: "".to_string(),
            reasoning_tokens: 0,
            context_tokens: 0,
            trust_score: 0.0,
            verdict: "".to_string(),
        }
    }

    pub fn from_chain(chain: &ReasoningChain) -> Self {
        IRLTelemetry {
            timestamp: Utc::now(),
            event_type: "reasoning_chain".to_string(),
            data: serde_json::to_string(chain).unwrap_or_else(|_| "{}".to_string()),
            chain_id: chain.audit.chain_id.clone(),
            reasoning_tokens: chain.reasoning.len(),
            context_tokens: chain.context.len(),
            trust_score: chain.irl.score,
            verdict: format!("{:?}", chain.verdict),
        }
    }

    pub fn record_decision(&self, event: &crate::audit::AuditEvent, score: f32, allowed: bool) {
        let decision_telemetry = IRLTelemetry {
            timestamp: Utc::now(),
            event_type: "trust_decision".to_string(),
            data: format!(
                "Event: {} by {} on {}",
                event.action,
                event.who,
                event.target.as_deref().unwrap_or("unknown")
            ),
            chain_id: "".to_string(),
            reasoning_tokens: 0,
            context_tokens: 0,
            trust_score: score,
            verdict: if allowed {
                "Allow".to_string()
            } else {
                "Deny".to_string()
            },
        };

        if let Err(e) = decision_telemetry.write_to_file("logs/decisions.jsonl") {
            eprintln!("[TELEMETRY] Failed to record decision: {e}");
        }
    }

    pub fn write_to_file(&self, path: &str) -> std::io::Result<()> {
        // Ensure directory exists
        if let Some(parent) = Path::new(path).parent() {
            create_dir_all(parent)?;
        }

        let file = OpenOptions::new().create(true).append(true).open(path)?;

        let mut writer = std::io::BufWriter::new(file);
        let json = serde_json::to_string(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        writeln!(writer, "{json}")?;
        writer.flush()?;

        Ok(())
    }
}
