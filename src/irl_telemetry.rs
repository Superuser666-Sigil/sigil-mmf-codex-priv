// Canon-Compliant irl_telemetry.rs
// Purpose: Emit trust data and decision traces to file, stdout, or other sinks

use crate::irl_explainer::ExplanationTrace;
use crate::audit::{AuditEvent, LogLevel};
use chrono::Utc;
use std::fs::{OpenOptions};
use std::io::Write;

pub enum TelemetryTarget {
    Stdout,
    File(String),
    Discard,
}

pub struct TelemetrySink {
    pub target: TelemetryTarget,
    pub severity_threshold: LogLevel,
}

impl TelemetrySink {
    pub fn new(target: TelemetryTarget, severity_threshold: LogLevel) -> Self {
        Self { target, severity_threshold }
    }

    pub fn emit(&self, trace: &ExplanationTrace) -> Result<AuditEvent, String> {
        if trace.audit.severity < self.severity_threshold {
            return Ok(trace.audit.clone()); // below threshold: silent
        }

        match &self.target {
            TelemetryTarget::Stdout => {
                println!("{}", serde_json::to_string_pretty(trace).map_err(|e| e.to_string())?);
            }
            TelemetryTarget::File(path) => {
                let mut file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|e| format!("Failed to open telemetry log: {}", e))?;

                writeln!(file, "{}", serde_json::to_string(trace).map_err(|e| e.to_string())?)
                    .map_err(|e| format!("Failed to write trace: {}", e))?;
            }
            TelemetryTarget::Discard => { /* no-op */ }
        }

        Ok(trace.audit.clone())
    }
}
