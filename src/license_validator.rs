// Canon-Compliant license_validator.rs
// Purpose: Validate sigil_license.toml format, emit audit, and return telemetry-safe results

use crate::audit::{AuditEvent, LogLevel};
use crate::loa::LOA;
use crate::canonicalize::canonicalize_json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use toml;
use sha2::{Sha256, Digest};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::Verifier;

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
    pub trust_score: f32,
    pub audit: AuditEvent,
}

/// Validates a sigil_license.toml file against Canon rules and trust policy
pub fn validate_license(
    path: &str,
    expected_runtime: &str,
    expected_fingerprint: &str,
) -> Result<LicenseValidationResult, String> {
    let content = fs::read_to_string(Path::new(path))
        .map_err(|e| format!("Failed to read license file: {e}"))?;
    validate_license_content(&content, expected_runtime, expected_fingerprint)
}

/// Validate license TOML content from a string. Supports both legacy [license.trust]
/// and new sealed format with top-level [license] + [seal].
pub fn validate_license_content(
    content: &str,
    expected_runtime: &str,
    expected_fingerprint: &str,
) -> Result<LicenseValidationResult, String> {
    #[derive(Deserialize)]
    struct LicenseWrapper {
        license: SigilLicense,
    }

    // Try legacy/compat format first
    let parsed_legacy: Result<LicenseWrapper, toml::de::Error> = toml::from_str(content);

    let license: SigilLicense = if let Ok(wrapper) = parsed_legacy {
        wrapper.license
    } else {
        // Try sealed format: { license: Simple, seal: Seal }
        #[derive(Clone, Debug, Serialize, Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct SimpleLicense {
            pub id: Option<String>,
            pub issued_at: DateTime<Utc>,
            pub expires_at: DateTime<Utc>,
            pub loa: LOA,
            pub owner: LicenseOwner,
            pub bindings: LicenseBindings,
        }
        #[derive(Clone, Debug, Serialize, Deserialize)]
        struct Seal {
            pub alg: String,
            pub sig: String,
            pub pubkey: String,
            #[serde(rename = "contentHash")]
            pub content_hash: String,
        }
        #[derive(Deserialize)]
        struct SealedFile {
            license: SimpleLicense,
            seal: Seal,
        }

        let sealed: SealedFile = toml::from_str(content)
            .map_err(|e| format!("Deserialize error: {e}"))?;

        // Verify sealed license: canonicalize license -> hash -> compare -> verify signature over canonical bytes
        let lic_val = serde_json::to_value(&sealed.license)
            .map_err(|e| format!("Serialize license failed: {e}"))?;
        let canon_str = canonicalize_json(&lic_val)
            .map_err(|e| format!("Canonicalize license failed: {e}"))?;
        let digest = Sha256::digest(canon_str.as_bytes());
        let digest_b64 = B64.encode(digest);
        if digest_b64 != sealed.seal.content_hash {
            return Err("License seal content hash mismatch".into());
        }
        let sig_bytes = B64
            .decode(&sealed.seal.sig)
            .map_err(|_| "Invalid signature encoding")?;
        if sig_bytes.len() != 64 {
            return Err("Invalid signature length".into());
        }
        let signature = ed25519_dalek::Signature::from_bytes(
            sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| "sig bytes")?,
        );
        let pk_bytes = B64
            .decode(&sealed.seal.pubkey)
            .map_err(|_| "Invalid public key encoding")?;
        if pk_bytes.len() != 32 {
            return Err("Invalid public key length".into());
        }
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
            pk_bytes
                .as_slice()
                .try_into()
                .map_err(|_| "pk bytes")?,
        )
        .map_err(|_| "Invalid verifying key")?;
        verifying_key
            .verify(canon_str.as_bytes(), &signature)
            .map_err(|_| "License signature verification failed")?;

        // Map SimpleLicense + seal into SigilLicense shape for validation output
        let permissions = LicensePermissions {
            can_mutate_canon: matches!(sealed.license.loa, LOA::Root | LOA::Mentor),
            can_override_audit: matches!(sealed.license.loa, LOA::Root),
            can_register_module: matches!(
                sealed.license.loa,
                LOA::Root | LOA::Mentor | LOA::Operator
            ),
            can_elevate_identity: matches!(sealed.license.loa, LOA::Root | LOA::Mentor),
        };
        let trust = LicenseTrust {
            trust_model: format!("sealed_{}", sealed.seal.alg),
            signature: sealed.seal.sig,
            sealed: true,
        };
        let audit = LicenseAudit {
            last_verified: Utc::now(),
            verifier: "license_validator".to_string(),
            canonicalized: true,
        };
        SigilLicense {
            id: sealed.license.id.unwrap_or_else(|| "sealed-license".to_string()),
            issued_at: sealed.license.issued_at,
            expires_at: sealed.license.expires_at,
            loa: sealed.license.loa.clone(),
            scope: vec!["runtime:sigil".to_string()],
            issuer: "sigil_web".to_string(),
            version: "1.0".to_string(),
            owner: sealed.license.owner,
            bindings: sealed.license.bindings,
            trust,
            permissions,
            audit,
        }
    };

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
        Some(&license.id),
        "license_validator.rs",
        &license.loa,
    )
    .with_severity(if score >= 0.9 {
        LogLevel::Info
    } else {
        LogLevel::Warn
    });

    Ok(LicenseValidationResult {
        license,
        valid: score >= 0.9,
        message: msg,
        trust_score: score,
        audit,
    })
}

pub fn load_current_loa() -> Result<LOA, String> {
    Ok(LOA::Root)
}
