// extensions.rs – Modular runtime handler for Sigil.
// This file allows runtime extensions (e.g., Shadowrun modules) to be loaded, audited, and trusted dynamically.

use crate::audit::log_api_event;
use crate::canon_validator::validate_canon_file;
use crate::extension_runtime::{route_command as route_extension_handler, ExtensionCommand};
use crate::loa::{self, LOA};
use crate::module_scope::ModuleScope;
use crate::sigilctl::{log_loa_violation, notify_success, warn_user};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

/// Information tracked for each loaded extension.
#[derive(Clone, Debug)]
struct ExtensionInfo {
    required_loa: LOA,
}

static EXTENSION_REGISTRY: OnceLock<Mutex<HashMap<String, ExtensionInfo>>> = OnceLock::new();

fn registry() -> &'static Mutex<HashMap<String, ExtensionInfo>> {
    EXTENSION_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

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
            let required = LOA::from(loa);

            // Register the extension with its required LOA.
            if let Ok(mut map) = registry().lock() {
                map.insert(
                    name.to_string(),
                    ExtensionInfo {
                        required_loa: required.clone(),
                    },
                );
            }

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

// List all currently loaded extensions and their LOA requirements.
pub fn list_extensions() {
    match registry().lock() {
        Ok(map) => {
            if map.is_empty() {
                println!("[INFO] No extensions are currently loaded");
            } else {
                for (name, info) in map.iter() {
                    println!("- {name} (requires LOA: {})", info.required_loa);
                }
            }
        }
        Err(_) => warn_user("Failed to access extension registry"),
    }
}

// Unload an extension and remove it from the registry.
pub fn unload_extension(name: &str) -> Result<(), String> {
    match registry().lock() {
        Ok(mut map) => {
            if map.remove(name).is_some() {
                notify_success(&format!("Extension '{name}' unloaded"));
                Ok(())
            } else {
                Err(format!("Extension '{name}' is not loaded"))
            }
        }
        Err(_) => Err("Failed to access extension registry".into()),
    }
}

// Route extension commands dynamically with LOA enforcement.
pub fn route_extension_command(raw: &str, loa: &str) -> Result<String, String> {
    let user_loa = LOA::from(loa);
    let mut parts = raw.split_whitespace();
    let ext_name = parts
        .next()
        .ok_or_else(|| "Command missing extension name".to_string())?;
    let args: Vec<String> = parts.map(|s| s.to_string()).collect();

    let required = {
        match registry().lock() {
            Ok(map) => map
                .get(ext_name)
                .map(|info| info.required_loa.clone())
                .ok_or_else(|| format!("Extension '{ext_name}' not loaded"))?,
            Err(_) => return Err("Failed to access extension registry".into()),
        }
    };

    if let Err(e) = loa::enforce(required.clone(), user_loa.clone()) {
        warn_user(&e);
        log_loa_violation(&required, &user_loa);
        return Err(e);
    }

    let cmd = ExtensionCommand {
        name: ext_name.to_string(),
        args,
        loa: user_loa.clone(),
        scope: ModuleScope::new("anonymous", ext_name, "session"),
    };

    route_extension_handler(&cmd)
}
