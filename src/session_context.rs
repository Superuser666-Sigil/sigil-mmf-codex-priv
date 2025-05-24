// Canon-Compliant session_context.rs
// Purpose: Track runtime trust context, configuration, LOA, and identity during MMF + Sigil sessions

use chrono::{Utc};
use uuid::Uuid;
use crate::loa::LOA;
use crate::config::MMFConfig;
use crate::license_validator::SigilLicense;

#[derive(Debug, Clone)]
pub struct SessionContext {
    pub session_id: String,
    pub loa: LOA,
    pub config: MMFConfig,
    pub license: Option<SigilLicense>,
    pub ephemeral: bool,
}

impl SessionContext {
    pub fn new(config: MMFConfig, license: Option<SigilLicense>) -> Self {
        let loa = license
            .as_ref()
            .map(|l| l.loa)
            .unwrap_or(LOA::Observer);

        let session_id = format!(
            "{}-{}",
            Utc::now().format("%Y%m%d%H%M%S"),
            Uuid::new_v4()
        );

        Self {
            session_id,
            loa,
            config,
            license,
            ephemeral: detect_ephemeral_mode(),
        }
    }

    pub fn is_ephemeral(&self) -> bool {
        self.ephemeral
    }

    pub fn identity_hash(&self) -> String {
        self.license
            .as_ref()
            .map(|l| l.owner.hash_id.clone())
            .unwrap_or_else(|| "anon".into())
    }

    pub fn summary_string(&self) -> String {
        format!(
            "[Session: {}] LOA::{:?}, Owner: {}{}",
            self.session_id,
            self.loa,
            self.identity_hash(),
            if self.ephemeral { " (ephemeral)" } else { "" }
        )
    }
}

pub fn detect_ephemeral_mode() -> bool {
    std::env::var("SIGIL_EPHEMERAL").unwrap_or_else(|_| "0".into()) == "1"
}
