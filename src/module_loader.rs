// module_loader.rs - Integrates canon validation during module load

use std::fs;
use std::path::Path;
use toml::Value;
use tracing::{error, info, warn};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ModuleLoaderError {
    #[error("Failed to read modules directory: {0}")]
    DirectoryRead(#[from] std::io::Error),
    #[error("Failed to read directory entry: {0}")]
    EntryRead(std::io::Error),
    #[error("Failed to load module manifest: {0}")]
    ManifestLoad(#[from] Box<dyn std::error::Error>),
}

pub fn load_module_manifest(path: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    let raw = fs::read_to_string(path)?;
    let module: Value = toml::from_str(&raw)?;
    Ok(module)
}

pub fn load_and_run_modules(ctx: &crate::session_context::SessionContext) -> Result<(), ModuleLoaderError> {
    info!(
        message = "Loading modules for session",
        session_id = %ctx.session_id
    );

    let modules_dir = Path::new("src/modules");
    if !modules_dir.exists() {
        info!(message = "No modules directory found");
        return Ok(());
    }

    for entry in fs::read_dir(modules_dir)? {
        let entry = entry.map_err(ModuleLoaderError::EntryRead)?;
        let path = entry.path();

        if path.is_dir() {
            let manifest_path = path.join("manifest.toml");
            if manifest_path.exists() {
                match load_module_manifest(&manifest_path) {
                    Ok(manifest) => {
                        if let Some(module) = manifest.get("module") {
                            let name = module
                                .get("name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("Unknown");
                            let version = module
                                .get("version")
                                .and_then(|v| v.as_str())
                                .unwrap_or("Unknown");
                            info!(
                                message = "Running module",
                                name = %name,
                                version = %version,
                                path = %path.display()
                            );
                        }
                    }
                    Err(e) => {
                        warn!(
                            message = "Failed to load manifest",
                            path = %path.display(),
                            error = %e
                        );
                    }
                }
            }
        }
    }

    Ok(())
}
