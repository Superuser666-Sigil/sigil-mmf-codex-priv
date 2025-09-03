#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct RuntimeTrustConfig {
    pub enforcement_mode: String,
    pub active_model: Option<String>,
    pub threshold: f64,
    pub telemetry_enabled: bool,
    pub explanation_enabled: bool,
}

impl Default for RuntimeTrustConfig {
    fn default() -> Self {
        Self {
            enforcement_mode: "active".to_string(),
            active_model: None,
            threshold: 0.4,
            telemetry_enabled: false,
            explanation_enabled: false,
        }
    }
}

use crate::config_security::SecureConfig;
use figment::{
    Figment,
    providers::{Env, Format, Serialized, Toml},
};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct MMFConfig {
    pub license_secret: String,
    pub db_backend: String,
    #[serde(default)]
    pub irl: RuntimeTrustConfig,
    pub trust: TrustConfig,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct TrustConfig {
    #[serde(default = "default_loa")]
    pub default_loa: String,
    #[serde(default)]
    pub allow_operator_canon_write: bool,
    #[serde(default)]
    pub allow_admin_export: bool,
}

fn default_loa() -> String {
    "Observer".to_string()
}

impl Default for TrustConfig {
    fn default() -> Self {
        TrustConfig {
            default_loa: default_loa(),
            allow_operator_canon_write: false,
            allow_admin_export: false,
        }
    }
}

#[derive(serde::Serialize)]
struct MMFConfigDefaults {
    db_backend: String,
    #[serde(default)]
    irl: RuntimeTrustConfig,
    #[serde(default)]
    trust: TrustConfig,
}

pub fn load_config() -> Result<MMFConfig, Box<figment::Error>> {
    // Validate environment variables first
    if let Err(errors) = SecureConfig::validate_environment() {
        return Err(Box::new(figment::Error::from(format!(
            "Environment validation failed: {}",
            errors.join(", ")
        ))));
    }

    let figment = Figment::from(Serialized::defaults(MMFConfigDefaults {
        db_backend: "sled".into(),
        irl: RuntimeTrustConfig::default(),
        trust: TrustConfig::default(),
    }))
    .merge(Toml::file("mmf.toml"))
    .merge(Env::prefixed("MMF_"));

    let config: MMFConfig = figment.extract()?;

    if config.license_secret.trim().is_empty() {
        return Err(Box::new(figment::Error::from("license_secret must be set")));
    }

    Ok(config)
}

/// Load configuration with enhanced security
pub fn load_secure_config(master_key: &str) -> Result<MMFConfig, Box<figment::Error>> {
    // Create secure config instance
    let secure_config = SecureConfig::new(master_key).map_err(|e| {
        Box::new(figment::Error::from(format!(
            "Secure config initialization failed: {e}"
        )))
    })?;

    // Try to load encrypted config first
    if let Ok(config) = secure_config.load_encrypted::<MMFConfig>("mmf.encrypted.toml") {
        return Ok(config);
    }

    // Fall back to regular config loading
    load_config()
}
