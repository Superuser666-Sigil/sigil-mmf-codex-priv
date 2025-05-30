
// extensions.rs – Modular runtime handler for Sigil.
// This file allows runtime extensions (e.g., Shadowrun modules) to be loaded, audited, and trusted dynamically.

use crate::audit_store::write_chain;
use crate::trust_registry::{register_scope, release_scope};
use std::path::Path;
use crate::canon_validator::validate_canon_file;
use crate::audit::log_api_event;
use crate::sigilctl::{warn_user, notify_success, log_loa_violation};

// Load an extension module based on its folder name and the active LOA.
// Example: load_extension("mmf-shadowrun-core", "Operator")
pub fn load_extension(name: &str, loa: &str) -> Result<(), String> {
    let manifest_path = format!("modules/{}/manifest.toml", name);
    let canon_path = format!("modules/{}/canon/sr6e.json", name);

    // Log the API/module event for trust visibility
    log_api_event("/module_load", "internal", 200, loa);

    // Validate the canon structure as part of the trust model
    let canon = Path::new(&canon_path);
    match validate_canon_file(&canon) {
        Ok(_) => {
            notify_success(&format!("Extension '{}' loaded at LOA: {}", name, loa));
            Ok(())
        },
        Err(e) => {
            warn_user(&format!("Failed to validate extension canon: {}", e));
            log_loa_violation("load_extension", "Trusted LOA", loa);
            Err(format!("Extension '{}' failed to validate: {}", name, e))
        }
    }
}

// Register an extension (future use: dynamic registry, trust pre-checks)
pub fn register_extension(_name: &str) {
    // Placeholder for runtime extension registry
    notify_success("Extension registered (placeholder)");
}

// List all currently available extensions (stub)
pub fn list_extensions() {
    println!("[INFO] Listing available extensions (stub)");
}

// Unload an extension (stub)
pub fn unload_extension(name: &str) {
    println!("[INFO] Extension '{}' unload requested (stub)", name);
}

// Route extension commands dynamically (placeholder)
pub fn route_extension_command(command: &str, loa: &str) {
    println!("[ROUTE] Executing command '{}' at LOA: {}", command, loa);
}