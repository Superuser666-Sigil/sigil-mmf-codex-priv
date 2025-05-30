use chrono::{DateTime, Utc};
use crate::loa::LOA;

pub struct AuditEvent {
    pub who: String,
    pub action: String,
    pub target: Option<String>,
    pub session_id: String,
    pub loa: LOA,
    pub timestamp: DateTime<Utc>,
    pub ephemeral: bool,
}

impl AuditEvent {
    pub fn new(who: &str, action: &str, target: Option<&str>, session_id: &str, loa: &LOA) -> Self {
        AuditEvent {
            who: who.to_string(),
            action: action.to_string(),
            target: target.map(str::to_string),
            session_id: session_id.to_string(),
            loa: loa.clone(),
            timestamp: Utc::now(),
            ephemeral: false,
        }
    }

    pub fn write_to_log(&self) {
        println!("[AUDIT] {} did {} on {:?} @ {}", self.who, self.action, self.target, self.timestamp);
    }
}
