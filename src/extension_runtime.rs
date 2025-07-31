use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crate::loa::LoaLevel;
use crate::module_scope::ModuleScope;
use crate::errors::{SigilResult, SafeLock};
use log::{info, warn, error};

#[derive(Debug, Clone)]
pub struct ExtensionCommand {
    pub name: String,
    pub args: Vec<String>,
    pub loa: LoaLevel,
    pub scope: ModuleScope,
}

pub trait Extension: Send + Sync {
    fn handle(&self, command: &ExtensionCommand) -> Result<String, String>;
}

static REGISTRY: OnceLock<Mutex<HashMap<String, Box<dyn Extension>>>> = OnceLock::new();

pub fn register_extension_handler(name: &str, handler: Box<dyn Extension>) -> SigilResult<()> {
    let map = REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    
    match map.safe_lock() {
        Ok(mut registry) => {
            registry.insert(name.to_string(), handler);
            info!("Successfully registered extension handler: {name}");
            Ok(())
        },
        Err(e) => {
            error!("Failed to acquire registry lock for extension {name}: {e}");
            Err(e)
        }
    }
}

pub fn route_command(command: &ExtensionCommand) -> Result<String, String> {
    let map = REGISTRY.get().ok_or("Extension registry not initialized")?;
    
    let handlers = match map.safe_lock() {
        Ok(registry) => registry,
        Err(e) => {
            error!("Failed to acquire registry lock for command routing: {e}");
            return Err("Registry lock failed".to_string());
        }
    };
    
    let handler = handlers.get(&command.name).ok_or("Extension not found")?;
    info!("Routing command '{}' to extension handler", command.name);
    handler.handle(command)
}

pub fn list_registered_extensions() -> Vec<String> {
    if let Some(map) = REGISTRY.get() {
        match map.safe_lock() {
            Ok(handlers) => {
                let extensions: Vec<String> = handlers.keys().cloned().collect();
                info!("Listing {} registered extensions", extensions.len());
                extensions
            },
            Err(e) => {
                error!("Failed to acquire registry lock for listing extensions: {e}");
                vec![]
            }
        }
    } else {
        warn!("Extension registry not initialized");
        vec![]
    }
}