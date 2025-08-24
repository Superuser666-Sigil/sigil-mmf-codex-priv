use crate::errors::{SafeLock, SigilError, SigilResult};
use crate::loa::LOA;
use crate::log_sink::LogEvent;
use crate::secure_audit_chain::{SecureAuditChain, ImmutableAuditStore};
use chrono::{DateTime, Utc};
use lazy_static::lazy_static;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Mutex;

lazy_static! {
    static ref AUDIT_LOG: Mutex<Vec<AuditEvent>> = Mutex::new(Vec::new());
    static ref API_EVENTS: Mutex<HashMap<String, u32>> = Mutex::new(HashMap::new());
    static ref SECURE_AUDIT_STORE: Mutex<Option<ImmutableAuditStore>> = Mutex::new(None);
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub who: String,
    pub action: String,
    pub target: Option<String>,
    pub session_id: String,
    pub loa: LOA,
    pub timestamp: DateTime<Utc>,
    pub ephemeral: bool,
    pub severity: LogLevel,
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
            severity: LogLevel::Info,
        }
    }

    pub fn with_severity(mut self, severity: LogLevel) -> Self {
        self.severity = severity;
        self
    }

    pub fn with_context(mut self, context: &str) -> Self {
        // Add context to the action
        self.action = format!("{} [Context: {}]", self.action, context);
        self
    }

    pub fn write_to_log(&self) -> SigilResult<()> {
        // Use proper logging instead of println!
        match self.severity {
            LogLevel::Info => info!(
                "[AUDIT] {} did {} on {:?} @ {}",
                self.who, self.action, self.target, self.timestamp
            ),
            LogLevel::Warn => warn!(
                "[AUDIT] {} did {} on {:?} @ {}",
                self.who, self.action, self.target, self.timestamp
            ),
            LogLevel::Error => error!(
                "[AUDIT] {} did {} on {:?} @ {}",
                self.who, self.action, self.target, self.timestamp
            ),
            LogLevel::Critical => error!(
                "[AUDIT CRITICAL] {} did {} on {:?} @ {}",
                self.who, self.action, self.target, self.timestamp
            ),
        }

        // Store in memory log using safe lock
        match AUDIT_LOG.safe_lock() {
            Ok(mut log) => {
                log.push(self.clone());
                debug!(
                    "Added audit event to memory log, total events: {}",
                    log.len()
                );
            }
            Err(e) => {
                error!("Failed to acquire audit log lock: {e}");
                return Err(SigilError::audit("Failed to store audit event in memory"));
            }
        }

        // Write to file
        let log_event = LogEvent::new_with_context(
            match self.severity {
                LogLevel::Info => "info",
                LogLevel::Warn => "warn",
                LogLevel::Error => "error",
                LogLevel::Critical => "critical",
            },
            &format!("{} did {} on {:?}", self.who, self.action, self.target),
            Some(&self.session_id),
            Some("audit"),
        );

        log_event
            .write_to("logs/audit.log")
            .map_err(|e| SigilError::audit(format!("Failed to write audit log: {e}")))?;

        Ok(())
    }
}

pub fn log_api_event(event: &str, scope: &str, status_code: u16, loa: &str) -> SigilResult<()> {
    // Track API event frequency using safe lock
    match API_EVENTS.safe_lock() {
        Ok(mut events) => {
            let key = format!("{event}:{scope}");
            *events.entry(key).or_insert(0) += 1;
            debug!("Tracked API event: {event}:{scope}");
        }
        Err(e) => {
            error!("Failed to acquire API events lock: {e}");
            return Err(SigilError::audit("Failed to track API event"));
        }
    }

    // Parse LOA from string - already handles errors properly
    let loa_enum = LOA::from_str(loa).unwrap_or(LOA::Guest);

    // Create audit event for API call
    let audit_event = AuditEvent::new("api_client", event, Some(scope), "api_session", &loa_enum)
        .with_severity(if status_code >= 400 {
            LogLevel::Error
        } else {
            LogLevel::Info
        })
        .with_context(&format!("Status: {status_code}, LOA: {loa}"));

    audit_event
        .write_to_log()
        .map_err(|e| SigilError::audit(format!("Failed to write API audit event: {e}")))
}

pub fn log_audit_event(
    event_type: &str,
    target: Option<&str>,
    _details: &str,
    severity: &str,
    timestamp: DateTime<Utc>,
) -> Result<(), String> {
    let severity_level = match severity.to_lowercase().as_str() {
        "error" => LogLevel::Error,
        "warn" => LogLevel::Warn,
        _ => LogLevel::Info,
    };

    let audit_event = AuditEvent {
        who: "system".to_string(),
        action: event_type.to_string(),
        target: target.map(str::to_string),
        session_id: "system".to_string(),
        loa: LOA::Observer, // Default for system events
        timestamp,
        ephemeral: false,
        severity: severity_level,
    };

    audit_event
        .write_to_log()
        .map_err(|e| format!("Failed to write audit event: {e}"))
}

pub fn get_audit_history() -> Vec<AuditEvent> {
    match AUDIT_LOG.safe_lock() {
        Ok(log) => {
            info!("Retrieved {} audit events from history", log.len());
            log.clone()
        }
        Err(e) => {
            error!("Failed to acquire audit log lock for history retrieval: {e}");
            Vec::new()
        }
    }
}

pub fn get_api_event_stats() -> HashMap<String, u32> {
    match API_EVENTS.safe_lock() {
        Ok(events) => {
            info!("Retrieved statistics for {} API event types", events.len());
            events.clone()
        }
        Err(e) => {
            error!("Failed to acquire API events lock for statistics: {e}");
            HashMap::new()
        }
    }
}

/// Initialize secure audit store with cryptographic integrity
pub fn init_secure_audit_store(storage_path: String, signing_key: ed25519_dalek::SigningKey) -> SigilResult<()> {
    match SECURE_AUDIT_STORE.safe_lock() {
        Ok(mut store) => {
            let audit_store = ImmutableAuditStore::new(storage_path, signing_key);
            *store = Some(audit_store);
            info!("Secure audit store initialized with cryptographic integrity");
            Ok(())
        }
        Err(e) => {
            error!("Failed to acquire secure audit store lock: {e}");
            Err(SigilError::audit("Failed to initialize secure audit store"))
        }
    }
}

/// Write audit event to secure audit chain
pub fn write_secure_audit_event(event: &AuditEvent, signing_key: &ed25519_dalek::SigningKey) -> SigilResult<()> {
    // Convert AuditEvent to AuditData for secure chain
    let audit_data = crate::secure_audit_chain::AuditData {
        user_id: event.who.clone(),
        action: event.action.clone(),
        resource: event.target.clone().unwrap_or_default(),
        session_id: event.session_id.clone(),
        loa: format!("{:?}", event.loa),
        metadata: {
            let mut meta = std::collections::HashMap::new();
            meta.insert("severity".to_string(), format!("{:?}", event.severity));
            meta.insert("ephemeral".to_string(), event.ephemeral.to_string());
            meta.insert("timestamp".to_string(), event.timestamp.to_rfc3339());
            meta
        },
    };
    
    match SECURE_AUDIT_STORE.safe_lock() {
        Ok(store) => {
            if let Some(ref audit_store) = *store {
                // Create secure audit chain entry
                let chain = SecureAuditChain::create_chain(
                    audit_data,
                    &[], // No parent chains for individual events
                    signing_key
                ).map_err(|e| SigilError::audit(format!("Failed to create secure audit chain: {e}")))?;
                
                // Store in immutable audit log
                audit_store.write_chain(&chain)
                    .map_err(|e| SigilError::audit(format!("Failed to store secure audit chain: {e}")))?;
                
                info!("Audit event written to secure audit chain");
                Ok(())
            } else {
                // Fall back to regular audit logging if secure store not initialized
                warn!("Secure audit store not initialized, falling back to regular logging");
                event.write_to_log()
            }
        }
        Err(e) => {
            error!("Failed to acquire secure audit store lock: {e}");
            Err(SigilError::audit("Failed to write secure audit event"))
        }
    }
}
