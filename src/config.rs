// Canon-Compliant MMFConfig.rs
// Purpose: Centralized, audit-safe runtime configuration for MMF + Sigil

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MMFConfig {
    pub data_dir: String,
    pub audit_log_path: String,
    pub encryption_key_b64: Option<String>,
    pub trust: TrustSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustSettings {
    pub allow_operator_canon_write: bool,
}

impl MMFConfig {
    /// Load configuration from a JSON file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file: {}", e))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("Invalid JSON config: {}", e))
    }

    /// Canonical validator for env-based configuration
    pub fn from_env() -> Result<Self, String> {
        let data_dir = std::env::var("MMF_DATA_DIR")
            .map_err(|_| "Missing MMF_DATA_DIR environment variable")?;

        if data_dir.trim().is_empty() {
            return Err("MMF_DATA_DIR cannot be empty".into());
        }

        let audit_log_path = std::env::var("MMF_AUDIT_LOG")
            .map_err(|_| "Missing MMF_AUDIT_LOG environment variable")?;

        if audit_log_path.trim().is_empty() {
            return Err("MMF_AUDIT_LOG cannot be empty".into());
        }

        let encryption_key_b64 = std::env::var("SIGIL_AES_KEY").ok();

        let allow_operator_canon_write = std::env::var("MMF_TRUST_OP_WRITE")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(true); // Default to true if not present

        Ok(Self {
            data_dir,
            audit_log_path,
            encryption_key_b64,
            trust: TrustSettings {
                allow_operator_canon_write,
            },
        })
    }
}