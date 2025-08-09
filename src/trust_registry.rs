use crate::loa::LOA;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::Mutex;

lazy_static! {
    static ref TRUST_REGISTRY: Mutex<HashMap<String, LOA>> = Mutex::new(HashMap::new());
}

pub fn register_scope(scope: &str, loa: &LOA) -> Result<(), String> {
    let mut registry = TRUST_REGISTRY
        .lock()
        .map_err(|_| "Failed to acquire registry lock".to_string())?;

    if registry.contains_key(scope) {
        return Err(format!("Scope '{scope}' is already registered"));
    }

    registry.insert(scope.to_string(), loa.clone());
    println!("[TRUST_REGISTRY] Registered scope '{scope}' with LOA: {loa:?}");

    Ok(())
}

pub fn release_scope(scope: &str) -> Result<(), String> {
    let mut registry = TRUST_REGISTRY
        .lock()
        .map_err(|_| "Failed to acquire registry lock".to_string())?;

    if registry.remove(scope).is_some() {
        println!("[TRUST_REGISTRY] Released scope '{scope}'");
        Ok(())
    } else {
        Err(format!("Scope '{scope}' not found in registry"))
    }
}

pub fn get_scope_loa(scope: &str) -> Option<LOA> {
    let registry = TRUST_REGISTRY.lock().ok()?;
    registry.get(scope).cloned()
}

pub fn list_registered_scopes() -> Vec<String> {
    if let Ok(registry) = TRUST_REGISTRY.lock() {
        registry.keys().cloned().collect()
    } else {
        Vec::new()
    }
}

pub fn clear_registry() -> Result<(), String> {
    let mut registry = TRUST_REGISTRY
        .lock()
        .map_err(|_| "Failed to acquire registry lock".to_string())?;

    let count = registry.len();
    registry.clear();
    println!("[TRUST_REGISTRY] Cleared {count} registered scopes");

    Ok(())
}
