//! Secure configuration management with encryption
//!
//! This module enhances configuration security with encrypted storage
//! as specified in Phase 2.6 of the security audit plan.

use crate::sigil_encrypt::{decode_base64_key, decrypt, encrypt};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::fs;
use std::path::Path;

/// Secure configuration with encrypted storage
pub struct SecureConfig {
    master_key: [u8; 32],
}

impl SecureConfig {
    /// Create a new secure configuration manager
    pub fn new(master_key: &str) -> Result<Self, String> {
        let key = decode_base64_key(master_key).map_err(|e| format!("Invalid master key: {e}"))?;

        Ok(SecureConfig { master_key: key })
    }

    /// Load encrypted configuration from file
    pub fn load_encrypted<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, String> {
        let encrypted_data =
            fs::read(path).map_err(|e| format!("Failed to read config file: {e}"))?;

        if encrypted_data.len() < 12 {
            return Err("Invalid encrypted config format".to_string());
        }

        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce: [u8; 12] = nonce_bytes
            .try_into()
            .map_err(|_| "Invalid nonce format".to_string())?;

        let decrypted = decrypt(ciphertext, &self.master_key, &nonce)
            .map_err(|e| format!("Failed to decrypt config: {e}"))?;

        serde_json::from_slice(&decrypted).map_err(|e| format!("Failed to parse config: {e}"))
    }

    /// Save configuration encrypted to file
    pub fn save_encrypted<T: Serialize>(&self, config: &T, path: &str) -> Result<(), String> {
        let json_data =
            serde_json::to_vec(config).map_err(|e| format!("Failed to serialize config: {e}"))?;

        let (ciphertext, nonce) = encrypt(&json_data, &self.master_key)
            .map_err(|e| format!("Failed to encrypt config: {e}"))?;

        let mut encrypted_data = nonce.to_vec();
        encrypted_data.extend_from_slice(&ciphertext);

        fs::write(path, encrypted_data).map_err(|e| format!("Failed to write config file: {e}"))
    }

    /// Validate environment variables comprehensively
    pub fn validate_environment() -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Required environment variables
        let required_vars = ["MMF_DATA_DIR", "MMF_AUDIT_LOG", "SIGIL_AES_KEY"];

        for var in &required_vars {
            if std::env::var(var).is_err() {
                errors.push(format!("Missing required environment variable: {var}"));
            }
        }

        // Validate SIGIL_AES_KEY format
        if let Ok(key) = std::env::var("SIGIL_AES_KEY") {
            if key.len() != 44 {
                // Base64 encoded 32-byte key
                errors.push("SIGIL_AES_KEY must be a valid base64-encoded 32-byte key".to_string());
            }

            if decode_base64_key(&key).is_err() {
                errors.push("SIGIL_AES_KEY must be valid base64".to_string());
            }
        }

        // Validate data directory
        if let Ok(data_dir) = std::env::var("MMF_DATA_DIR") {
            if data_dir.trim().is_empty() {
                errors.push("MMF_DATA_DIR cannot be empty".to_string());
            }

            if !Path::new(&data_dir).exists() {
                errors.push(format!("MMF_DATA_DIR '{data_dir}' does not exist"));
            }
        }

        // Validate audit log path
        if let Ok(audit_log) = std::env::var("MMF_AUDIT_LOG") {
            if audit_log.trim().is_empty() {
                errors.push("MMF_AUDIT_LOG cannot be empty".to_string());
            }

            // Ensure audit log directory exists
            if let Some(parent) = Path::new(&audit_log).parent()
                && !parent.exists() {
                    errors.push(format!(
                        "Audit log directory '{}' does not exist",
                        parent.display()
                    ));
            }
        }

        // Validate optional configuration
        if let Ok(trust_op_write) = std::env::var("MMF_TRUST_OP_WRITE") {
            let valid_values = ["true", "false", "0", "1"];
            if !valid_values.contains(&trust_op_write.to_lowercase().as_str()) {
                errors.push("MMF_TRUST_OP_WRITE must be 'true', 'false', '0', or '1'".to_string());
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Get configuration statistics
    pub fn get_config_stats(&self) -> ConfigStats {
        let mut stats = ConfigStats {
            total_vars: 0,
            required_vars: 0,
            optional_vars: 0,
            missing_vars: Vec::new(),
            invalid_vars: Vec::new(),
        };

        let all_vars = [
            "MMF_DATA_DIR",
            "MMF_AUDIT_LOG",
            "SIGIL_AES_KEY",
            "MMF_TRUST_OP_WRITE",
            "MMF_SIGIL_ENV",
            "RUST_LOG",
        ];

        for var in &all_vars {
            stats.total_vars += 1;

            match std::env::var(var) {
                Ok(value) => {
                    if ["MMF_DATA_DIR", "MMF_AUDIT_LOG", "SIGIL_AES_KEY"].contains(var) {
                        stats.required_vars += 1;
                    } else {
                        stats.optional_vars += 1;
                    }

                    // Validate specific variables
                    if *var == "SIGIL_AES_KEY" && value.len() != 44 {
                        stats.invalid_vars.push(var.to_string());
                    }
                }
                Err(_) => {
                    if ["MMF_DATA_DIR", "MMF_AUDIT_LOG", "SIGIL_AES_KEY"].contains(var) {
                        stats.missing_vars.push(var.to_string());
                    }
                }
            }
        }

        stats
    }
}

/// Configuration statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigStats {
    pub total_vars: usize,
    pub required_vars: usize,
    pub optional_vars: usize,
    pub missing_vars: Vec<String>,
    pub invalid_vars: Vec<String>,
}

/// Enhanced configuration with security metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureMMFConfig {
    pub data_dir: String,
    pub audit_log_path: String,
    pub encryption_key_b64: Option<String>,
    pub trust: TrustConfig,
    pub security_metadata: SecurityMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustConfig {
    pub allow_operator_canon_write: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMetadata {
    pub config_hash: String,
    pub encrypted_at: chrono::DateTime<chrono::Utc>,
    pub version: String,
    pub checksum: String,
}

impl SecureMMFConfig {
    /// Load configuration with enhanced security validation
    pub fn load_secure() -> Result<Self, String> {
        // Validate environment first
        SecureConfig::validate_environment()
            .map_err(|errors| format!("Environment validation failed: {}", errors.join(", ")))?;

        // Load from environment
        let data_dir = std::env::var("MMF_DATA_DIR")
            .map_err(|_| "Missing required env var: MMF_DATA_DIR".to_string())?;

        let audit_log_path = std::env::var("MMF_AUDIT_LOG")
            .map_err(|_| "Missing required env var: MMF_AUDIT_LOG".to_string())?;

        let encryption_key_b64 = std::env::var("SIGIL_AES_KEY").ok();

        let allow_operator_canon_write = std::env::var("MMF_TRUST_OP_WRITE")
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
            .map(|v| !(v == "false" || v == "0"))
            .unwrap_or(true);

        // Create security metadata
        let mut hasher = sha2::Sha256::new();
        hasher
            .update(format!("{data_dir}:{audit_log_path}:{allow_operator_canon_write}").as_bytes());
        let config_hash = format!("{:x}", hasher.finalize());

        let security_metadata = SecurityMetadata {
            config_hash,
            encrypted_at: chrono::Utc::now(),
            version: "1.0".to_string(),
            checksum: "".to_string(), // Will be calculated when saved
        };

        Ok(SecureMMFConfig {
            data_dir,
            audit_log_path,
            encryption_key_b64,
            trust: TrustConfig {
                allow_operator_canon_write,
            },
            security_metadata,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_config_creation() {
        // Create a test key (32 bytes base64 encoded)
        // Using a simple 32-byte key: all zeros
        let test_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

        let secure_config = SecureConfig::new(test_key);
        match secure_config {
            Ok(_) => (),
            Err(e) => panic!("Failed to create secure config: {}", e),
        }
    }

    #[test]
    fn test_config_serialization() {
        let config = SecureMMFConfig {
            data_dir: "/tmp/test".to_string(),
            audit_log_path: "/tmp/audit.log".to_string(),
            encryption_key_b64: Some("testkey".to_string()),
            trust: TrustConfig {
                allow_operator_canon_write: true,
            },
            security_metadata: SecurityMetadata {
                config_hash: "test_hash".to_string(),
                encrypted_at: chrono::Utc::now(),
                version: "1.0".to_string(),
                checksum: "test_checksum".to_string(),
            },
        };

        let json = serde_json::to_string(&config);
        assert!(json.is_ok());
    }
}
