// Phase 1 - Canon Extension: audit.rs
// Adds IRL linkage (trust score) and default severity to core audit structure

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;
use crate::loa::LOA;

/// Severity levels for structured log classification
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LogLevel {
    Info,
    Warn,
    Error,
    Debug,
    Critical,
}

/// Core audit event record passed between enforcement layers
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    pub id: String,
    pub session_id: String,
    pub timestamp: DateTime<Utc>,
    pub who: String,
    pub action: String,
    pub context: Option<String>,
    pub source: Option<String>,
    pub trace_id: String,
    pub tags: Option<Vec<String>>,
    pub severity: LogLevel,
    pub irl_score: Option<f32>,
}

impl AuditEvent {
    /// Generates a new audit event with required trace ID and source actor
    pub fn new(who: &str, action: &str, trace_id: &str, source: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            session_id: "session-anon".to_string(),
            timestamp: Utc::now(),
            who: who.to_string(),
            action: action.to_string(),
            context: None,
            source: Some(source.to_string()),
            trace_id: trace_id.to_string(),
            tags: None,
            severity: LogLevel::Info,
            irl_score: None,
        }
    }

    /// Sets log severity
    pub fn with_severity(mut self, level: LogLevel) -> Self {
        self.severity = level;
        self
    }

    /// Adds optional context string
    pub fn with_context(mut self, ctx: String) -> Self {
        self.context = Some(ctx);
        self
    }

    /// Writes to log output (placeholder)
    pub fn write_to_log(&self) -> Result<(), &'static str> {
        // This would normally stream to an external sink or file
        println!("[AUDIT] [{}] {} - {}", self.severity_string(), self.who, self.action);
        Ok(())
    }

    pub fn severity_string(&self) -> &'static str {
        match self.severity {
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
            LogLevel::Debug => "DEBUG",
            LogLevel::Critical => "CRITICAL",
        }
    }

    /// LOA-gated emit wrapper
    pub fn emit<T: AuditEmitAccess>(&self, loa: &T) -> Result<(), &'static str> {
        if !loa.can_emit() {
            return Err("LOA not permitted to emit audit logs");
        }
        self.write_to_log()
    }
}

/// Trait for controlling which LOA may emit audit logs
pub trait AuditEmitAccess {
    pub fn can_emit(&self) -> bool;
}

impl AuditEmitAccess for LOA {
    pub fn can_emit(&self) -> bool {
        matches!(self, LOA::Mentor | LOA::Root)
    }
}