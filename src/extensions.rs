// extensions.rs – Modular runtime handler for Sigil.
// This file allows runtime extensions (e.g., Shadowrun modules) to be loaded, audited, and trusted dynamically.

use crate::audit::log_api_event;
use crate::canon_validator::validate_canon_file;
use crate::loa::LOA;
use crate::sigilctl::{log_loa_violation, notify_success, warn_user};
use std::path::Path;

// Load an extension module based on its folder name and the active LOA.
// Example: load_extension("mmf-shadowrun-core", "Operator")
pub fn load_extension(name: &str, loa: &str) -> Result<(), String> {
    let canon_path = format!("modules/{name}/canon/sr6e.json");

    // Log the API/module event for trust visibility
    let _ = log_api_event("/module_load", "internal", 200, loa);

    // Validate the canon structure as part of the trust model
    let canon = Path::new(&canon_path);
    match validate_canon_file(canon) {
        Ok(_) => {
            notify_success(&format!("Extension '{name}' loaded at LOA: {loa}"));
            Ok(())
        }
        Err(e) => {
            warn_user(&format!("Failed to validate extension canon: {e}"));
            log_loa_violation(&LOA::Guest, &LOA::Operator);
            Err(format!("Extension '{name}' failed to validate: {e}"))
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
    println!("[INFO] Extension '{name}' unload requested (stub)");
}

// Route extension commands dynamically (placeholder)
pub fn route_extension_command(command: &str, loa: &str) {
    println!("[ROUTE] Executing command '{command}' at LOA: {loa}");
}
