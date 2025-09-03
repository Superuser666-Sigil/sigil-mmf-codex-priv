use serde::{Deserialize, Serialize};

/// Trust-related configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustConfig {
    pub allow_operator_canon_write: bool,
}

impl Default for TrustConfig {
    fn default() -> Self {
        // Historical behavior from tests: defaults to true when unset
        Self {
            allow_operator_canon_write: true,
        }
    }
}

/// Minimal runtime configuration expected by tests and early runtime wiring
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MMFConfig {
    pub data_dir: String,
    pub audit_log_path: String,
    pub encryption_key_b64: Option<String>,
    pub trust: TrustConfig,
}

impl MMFConfig {
    /// Load configuration strictly from environment variables.
    ///
    /// Required:
    /// - MMF_DATA_DIR
    /// - MMF_AUDIT_LOG
    ///
    /// Optional:
    /// - SIGIL_AES_KEY (base64)
    /// - MMF_TRUST_OP_WRITE (defaults to true; set to "false"/"0" to disable)
    pub fn from_env() -> Result<Self, String> {
        let data_dir = std::env::var("MMF_DATA_DIR")
            .map_err(|_| "Missing required env var: MMF_DATA_DIR".to_string())?;
        if data_dir.trim().is_empty() {
            return Err("MMF_DATA_DIR cannot be empty".to_string());
        }

        let audit_log_path = std::env::var("MMF_AUDIT_LOG")
            .map_err(|_| "Missing required env var: MMF_AUDIT_LOG".to_string())?;
        if audit_log_path.trim().is_empty() {
            return Err("MMF_AUDIT_LOG cannot be empty".to_string());
        }

        let encryption_key_b64 = std::env::var("SIGIL_AES_KEY")
            .ok()
            .filter(|s| !s.is_empty());

        let allow_operator_canon_write = std::env::var("MMF_TRUST_OP_WRITE")
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
            .map(|v| !(v == "false" || v == "0"))
            .unwrap_or(true);

        Ok(MMFConfig {
            data_dir,
            audit_log_path,
            encryption_key_b64,
            trust: TrustConfig {
                allow_operator_canon_write,
            },
        })
    }
}
