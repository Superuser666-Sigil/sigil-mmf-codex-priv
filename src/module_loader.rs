// Canon-Compliant module_loader.rs
// Purpose: Load MMF modules with Canon validation, trust audit, and telemetry

use std::fs;
use std::path::{Path, PathBuf};
use chrono::Utc;
use crate::canon_validator::{validate_canon_file, CanonValidatorSummary};
use crate::audit::{AuditEvent, LogLevel};

#[derive(Debug)]
pub struct ModuleLoadResult {
    pub success: bool,
    pub message: String,
    pub audit: AuditEvent,
    pub canon_validated: bool,
    pub validated_entries: usize,
}

pub fn load_module(manifest_path: &Path, canon_path: &Path) -> Result<ModuleLoadResult, String> {
    let raw = fs::read_to_string(manifest_path)
        .map_err(|e| format!("Failed to read manifest: {}", e))?;

    let module: toml::Value = toml::from_str(&raw)
        .map_err(|e| format!("Invalid TOML in manifest: {}", e))?;

    let module_id = module.get("module")
        .and_then(|m| m.get("id"))
        .and_then(|id| id.as_str())
        .unwrap_or("unknown");

    let audit = AuditEvent::new(
        "system",
        "load_module",
        module_id,
        "module_loader.rs"
    )
    .with_severity(LogLevel::Info)
    .with_context(format!("Attempting to load module manifest '{}'", manifest_path.display()));

    println!("📦 Loading module: {}", module_id);

    let canon_result: Result<CanonValidatorSummary, String> = validate_canon_file(canon_path);

    match canon_result {
        Ok(summary) => {
            println!("✅ Canon validated: {} entries", summary.entry_count);
            Ok(ModuleLoadResult {
                success: true,
                message: "Module loaded successfully".into(),
                audit,
                canon_validated: true,
                validated_entries: summary.entry_count,
            })
        }
        Err(e) => {
            let failed_audit = audit.with_severity(LogLevel::Error).with_context(format!(
                "Canon validation failed for '{}': {}",
                canon_path.display(),
                e
            ));
            Err(format!("❌ Module load failed: {}", e))
                .map(|_| ModuleLoadResult {
                    success: false,
                    message: e,
                    audit: failed_audit,
                    canon_validated: false,
                    validated_entries: 0,
                })
        }
    }
}
