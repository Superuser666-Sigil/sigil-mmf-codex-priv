// Phase 1 - Canon Extension: audit.rs
// Adds IRL linkage (trust score) and default severity to core audit structure

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

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
    /// Generates a new audit event with a required trace_id and default severity
    pub fn new<S: Into<String>>(session_id: S, who: S, action: S, trace_id: S) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            session_id: session_id.into(),
            timestamp: Utc::now(),
            who: who.into(),
            action: action.into(),
            context: None,
            source: None,
            trace_id: trace_id.into(),
            tags: None,
            severity: LogLevel::Info,           // ← Default
            irl_score: None,                    // ← Optional trust model linkage
        }
    }

    /// Enriches the event with contextual information
    pub fn with_context<S: Into<String>>(mut self, context: S) -> Self {
        self.context = Some(context.into());
        self
    }

    /// Sets the severity level of the event
    pub fn with_severity(mut self, level: LogLevel) -> Self {
        self.severity = level;
        self
    }

    /// Assigns the origin module or tool identifier
    pub fn from_source<S: Into<String>>(mut self, source: S) -> Self {
        self.source = Some(source.into());
        self
    }

    /// Adds tags to the audit event for later filtering or grouping
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = Some(tags);
        self
    }

    /// Links the event to an IRL model trust score
    pub fn with_irl_score(mut self, score: f32) -> Self {
        self.irl_score = Some(score);
        self
    }
}

impl fmt::Display for AuditEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} | {} -> {}{} (severity: {:?})",
            self.timestamp,
            self.session_id,
            self.who,
            self.action,
            match &self.context {
                Some(ctx) => format!(" [{}]", ctx),
                None => String::new(),
            },
            self.severity
        )
    }
}
