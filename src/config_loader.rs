#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct IRLConfig {
    pub enforcement_mode: String,
    pub active_model: Option<String>,
    pub threshold: f64,
    pub telemetry_enabled: bool,
    pub explanation_enabled: bool,
}

impl Default for IRLConfig {
    fn default() -> Self {
        Self {
            enforcement_mode: "shadow".to_string(),
            active_model: None,
            threshold: 0.0,
            telemetry_enabled: true,
            explanation_enabled: true,
        }
    }
}

use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct MMFConfig {
    pub license_secret: String,
    pub db_backend: String,
    #[serde(default)]
    pub irl: IRLConfig,
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
    irl: IRLConfig,
    #[serde(default)]
    trust: TrustConfig,
}

pub fn load_config() -> Result<MMFConfig, figment::Error> {
    let figment = Figment::from(Serialized::defaults(MMFConfigDefaults {
        db_backend: "sled".into(),
        irl: IRLConfig::default(),
        trust: TrustConfig::default(),
    }))
    .merge(Toml::file("mmf.toml"))
    .merge(Env::prefixed("MMF_"));

    let config: MMFConfig = figment.extract()?;

    if config.license_secret.trim().is_empty() {
        return Err(figment::Error::from("license_secret must be set"));
    }

    Ok(config)
}
