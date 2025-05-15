// Canon-Compliant log_sink.rs
// Purpose: Handle trusted runtime logging of system events, actions, and trust decisions

use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEvent {
    pub trace_id: String,
    pub component: String,
    pub event_type: String,
    pub context: String,
    pub level: LogLevel,
    pub timestamp: DateTime<Utc>,
}
