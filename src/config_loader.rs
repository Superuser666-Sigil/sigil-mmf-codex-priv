
#[derive(Debug, Clone, serde::Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
pub struct MMFConfig {
    pub license_secret: String,
    pub db_backend: String,
    #[serde(default)]
    pub irl:
  enforcement_mode: shadow
  threshold: 0.0
  telemetry_enabled: true
  explanation_enabled: true

trust: TrustConfig,
}

#[derive(Debug, Clone, Deserialize)]
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

pub fn load_config() -> MMFConfig {
    Figment::from(Serialized::defaults(MMFConfig {
        license_secret: "changeme".into(),
        db_backend: "sled".into(),
        irl:
  enforcement_mode: shadow
  threshold: 0.0
  telemetry_enabled: true
  explanation_enabled: true

trust: TrustConfig::default(),
    }))
    .merge(Toml::file("mmf.toml"))
    .merge(Env::prefixed("MMF_"))
    .extract()
    .expect("Failed to load MMF config")
}
