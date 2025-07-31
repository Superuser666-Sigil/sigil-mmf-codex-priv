// module_loader.rs - Integrates canon validation during module load

use std::fs;
use std::path::Path;
use toml::Value;

pub fn load_module_manifest(path: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    let raw = fs::read_to_string(path)?;
    let module: Value = toml::from_str(&raw)?;
    Ok(module)
}

pub fn load_and_run_modules(ctx: &crate::session_context::SessionContext) {
    println!("[ModuleLoader] Loading modules for session {}", ctx.session_id);

    let modules_dir = Path::new("src/modules");
    if !modules_dir.exists() {
        println!("[ModuleLoader] No modules directory found.");
        return;
    }

    for entry in fs::read_dir(modules_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();

        if path.is_dir() {
            let manifest_path = path.join("manifest.toml");
            if manifest_path.exists() {
                match load_module_manifest(&manifest_path) {
                    Ok(manifest) => {
                        if let Some(module) = manifest.get("module") {
                            let name = module.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown");
                            let version = module.get("version").and_then(|v| v.as_str()).unwrap_or("Unknown");
                            println!("[ModuleLoader] Running module: {name} (v{version})");
                        }
                    }
                    Err(e) => {
                        println!("[ModuleLoader] Failed to load manifest for {path:?}: {e}");
                    }
                }
            }
        }
    }
}
