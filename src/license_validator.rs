// Canon-Compliant license_validator.rs
// Purpose: Validate sigil_license.toml format, emit audit, and return telemetry-safe results

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use crate::audit::{AuditEvent, LogLevel};
use crate::loa::LOA;
use toml;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigilLicense {
    pub id: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub loa: LOA,
    pub scope: Vec<String>,
    pub issuer: String,
    pub version: String,
    pub owner: LicenseOwner,
    pub bindings: LicenseBindings,
    pub trust: LicenseTrust,
    pub permissions: LicensePermissions,
    pub audit: LicenseAudit,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LicenseOwner {
    pub name: String,
    pub mnemonic: String,
    pub email: String,
    pub hash_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LicenseBindings {
    pub canon_fingerprint: String,
    pub runtime_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LicenseTrust {
    pub trust_model: String,
    pub signature: String,
    pub sealed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LicensePermissions {
    pub can_mutate_canon: bool,
    pub can_override_audit: bool,
    pub can_register_module: bool,
    pub can_elevate_identity: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LicenseAudit {
    pub last_verified: DateTime<Utc>,
    pub verifier: String,
    pub canonicalized: bool,
}

#[derive(Clone, Debug)]
pub struct LicenseValidationResult {
    pub license: SigilLicense,
    pub valid: bool,
    pub message: String,
    pub irl_score: f32,
    pub audit: AuditEvent,
}

/// Validates a sigil_license.toml file against Canon rules and trust policy
pub fn validate_license(path: &str, expected_runtime: &str, expected_fingerprint: &str) -> Result<LicenseValidationResult, String> {
    let content = fs::read_to_string(Path::new(path))
        .map_err(|e| format!("Failed to read license file: {}", e))?;

    let parsed: toml::Value = toml::from_str(&content)
        .map_err(|e| format!("Invalid TOML format: {}", e))?;

    let license: SigilLicense = parsed.get("license")
        .ok_or("Missing [license] block".to_string())
        .and_then(|val| toml::from_str(&val.to_string()).map_err(|e| format!("Deserialize error: {}", e)))?;

    let now = Utc::now();
    let mut score = 1.0;
    let mut msg = "License is valid and trusted".to_string();

    if license.expires_at < now {
        score = 0.0;
        msg = "License expired".into();
    } else if license.bindings.runtime_id != expected_runtime {
        score = 0.2;
        msg = "Mismatched runtime ID".into();
    } else if license.bindings.canon_fingerprint != expected_fingerprint {
        score = 0.4;
        msg = "Mismatched canon fingerprint".into();
    } else if !license.trust.sealed {
        score = 0.5;
        msg = "License is not sealed".into();
    }

    let audit = AuditEvent::new(
        &license.owner.hash_id,
        "validate_license",
        &license.id,
        "license_validator.rs"
    )
    .with_severity(if score >= 0.9 { LogLevel::Info } else { LogLevel::Warn })
    .with_context(format!("License validation result: {}", msg).to_string());


    Ok(LicenseValidationResult {
        license,
        valid: score >= 0.9,
        message: msg,
        irl_score: score,
        audit,
    })
}

// Temporary stub: returns default LOA level
pub fn load_current_loa() -> LOA {
    // In a full implementation, you'd load the license and extract LOA
    // Here, we return Observer by default
    LOA::Observer
}