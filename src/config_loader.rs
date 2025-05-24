// Canon-Compliant Config Loader for MMF + Sigil
// Purpose: Load config from file or environment, emit audit trace, and support IRL-compatible results

use std::fs;
use std::path::Path;
use chrono::Utc;
use crate::config::MMFConfig;
use crate::audit::{AuditEvent, LogLevel};

#[derive(Debug)]
pub struct ConfigLoadResult {
    pub config: MMFConfig,
    pub audit: AuditEvent,
    pub irl_score: f32,
}

/// Attempts to load configuration from a JSON file, then environment as fallback
pub fn load_config(path: Option<&str>) -> Result<ConfigLoadResult, String> {
    let (config, source_note) = if let Some(path_str) = path {
        let content = fs::read_to_string(Path::new(path_str))
            .map_err(|e| format!("Failed to read config file '{}': {}", path_str, e))?;
        let cfg: MMFConfig = serde_json::from_str(&content)
            .map_err(|e| format!("Invalid config JSON in '{}': {}", path_str, e))?;
        (cfg, format!("Loaded from file: {}", path_str))
    } else {
        let cfg = MMFConfig::from_env()?;
        (cfg, "Loaded from environment defaults".into())
    };

    let audit = AuditEvent::new(
        "system",
        "load_config",
        "config-init",
        "config_loader.rs"
    )
    .with_severity(LogLevel::Info)
    .with_context(source_note);

    let irl_score = if config.trust.allow_operator_canon_write {
        0.9 // Slightly less than perfect due to elevated risk surface
    } else {
        1.0
    };

    Ok(ConfigLoadResult {
        config,
        audit,
        irl_score,
    })
}