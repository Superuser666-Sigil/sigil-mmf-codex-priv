use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crate::loa::LoaLevel;
use crate::module_scope::ModuleScope;

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

pub fn register_extension_handler(name: &str, handler: Box<dyn Extension>) {
    let map = REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    map.lock().unwrap().insert(name.to_string(), handler);
}

pub fn route_command(command: &ExtensionCommand) -> Result<String, String> {
    let map = REGISTRY.get().ok_or("Extension registry not initialized")?;
    let handlers = map.lock().unwrap();
    let handler = handlers.get(&command.name).ok_or("Extension not found")?;
    handler.handle(command)
}

pub fn list_registered_extensions() -> Vec<String> {
    if let Some(map) = REGISTRY.get() {
        let handlers = map.lock().unwrap();
        handlers.keys().cloned().collect()
    } else {
        vec![]
    }
}