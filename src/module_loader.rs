// module_loader.rs - Module loading and execution with LOA enforcement

use crate::errors::SigilResult;
use crate::loa::LOA;
use std::fs;
use std::path::Path;
use thiserror::Error;
use toml::Value;
use tracing::{error, info, warn};

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

/// SigilModule trait for secure module execution
pub trait SigilModule {
    fn required_loa(&self) -> LOA;
    fn run(&self, ctx: &ModuleContext) -> SigilResult<String>;
}

/// Module execution context
pub struct ModuleContext {
    pub session_id: String,
    pub user_id: String,
    pub loa: LOA,
    pub input: String,
}

/// Module registry for managing loaded modules
#[derive(Default)]
pub struct ModuleRegistry {
    modules: std::collections::HashMap<String, Box<dyn SigilModule + Send + Sync>>,
}

impl ModuleRegistry {
    pub fn new() -> Self {
        Self {
            modules: std::collections::HashMap::new(),
        }
    }

    pub fn register_module(&mut self, name: &str, module: Box<dyn SigilModule + Send + Sync>) {
        self.modules.insert(name.to_string(), module);
        info!("Registered module: {}", name);
    }

    pub fn get_module(&self, name: &str) -> Option<&(dyn SigilModule + Send + Sync)> {
        self.modules.get(name).map(|b| &**b)
    }

    pub fn run_module(&self, name: &str, ctx: &ModuleContext) -> SigilResult<String> {
        let module = self
            .get_module(name)
            .ok_or_else(|| crate::errors::SigilError::not_found("module", name))?;

        // Check LOA requirement
        if ctx.loa < module.required_loa() {
            return Err(crate::errors::SigilError::insufficient_loa(
                module.required_loa(),
                ctx.loa.clone(),
            ));
        }

        module.run(ctx)
    }
}

// Default is derived above

/// Built-in hello module for testing
pub struct HelloModule;

impl SigilModule for HelloModule {
    fn required_loa(&self) -> LOA {
        LOA::Operator
    }

    fn run(&self, ctx: &ModuleContext) -> SigilResult<String> {
        Ok(format!(
            "Hello from Sigil! Session: {}, User: {}, LOA: {:?}",
            ctx.session_id, ctx.user_id, ctx.loa
        ))
    }
}

pub fn load_and_run_modules(
    ctx: &crate::session_context::SessionContext,
) -> Result<(), ModuleLoaderError> {
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
