// Canon-Compliant log_sink.rs
// Purpose: Handle trusted runtime logging of system events, actions, and trust decisions

use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use crate::loa::LOA;

/// LogLevel classifies the severity of log output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
}

/// LogEvent is a structured record of runtime activity.
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

impl LogEvent {
    /// Emit this log event to stdout or log sink, gated by LOA-based access.
    pub fn emit<T: LogSinkAccess>(&self, loa: &T) -> Result<(), &'static str> {
        if !loa.can_log(self.level) {
            return Err("LOA not permitted to emit log event at this level");
        }

        println!("[LOG] {} | {} | {} | {}", self.level_string(), self.component, self.event_type, self.context);
        Ok(())
    }

    fn level_string(&self) -> &'static str {
        match self.level {
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
            LogLevel::Fatal => "FATAL",
        }
    }
}

/// Trait that defines LOA-based control over what can be logged.
pub trait LogSinkAccess {
    fn can_log(&self, level: LogLevel) -> bool;
}

impl LogSinkAccess for LOA {
    fn can_log(&self, level: LogLevel) -> bool {
        match self {
            LOA::Root => true,
            LOA::Mentor => true,
            LOA::Operator => level <= LogLevel::Warn,
            LOA::Observer => level <= LogLevel::Info,
        }
    }
}
