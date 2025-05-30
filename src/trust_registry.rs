use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::module_scope::ModuleScope;

/// TTL for each request scope (e.g., 10 seconds per isolated MMF task)
const SCOPE_TTL: Duration = Duration::from_secs(10);

/// Tracks active module scopes and when they expire
static TRUST_CONTEXTS: OnceLock<Mutex<HashMap<ModuleScope, Instant>>> = OnceLock::new();

/// Attempt to register a new request scope. Fails if already in use and unexpired.
pub fn register_scope(scope: &ModuleScope) -> Result<(), String> {
    let registry = TRUST_CONTEXTS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut active = registry.lock().unwrap();

    // Clean expired entries before checking
    active.retain(|_, &mut expiry| expiry.elapsed() < SCOPE_TTL);

    if active.contains_key(scope) {
        return Err(format!(
            "Scope {} is already active. Try again after cooldown.",
            scope.label()
        ));
    }

    active.insert(scope.clone(), Instant::now());
    Ok(())
}

/// Remove a scope manually (e.g., after successful command or cancel)
pub fn release_scope(scope: &ModuleScope) {
    if let Some(registry) = TRUST_CONTEXTS.get() {
        let mut active = registry.lock().unwrap();
        active.remove(scope);
    }
}

/// For diagnostic use: show active scoped sessions
pub fn list_active_scopes() -> Vec<String> {
    if let Some(registry) = TRUST_CONTEXTS.get() {
        let active = registry.lock().unwrap();
        active.keys().map(|s| s.label()).collect()
    } else {
        Vec::new()
    }
}