//! End-to-end tests for module execution with LOA enforcement
//! 
//! Tests the acceptance criteria for Track D1:
//! - Operator LOA → 200 with content
//! - Guest → 403

use crate::sigil_runtime_core::SigilRuntimeCore;
use crate::canon_store_sled::CanonStoreSled;
use crate::runtime_config::{EnforcementMode, RuntimeConfig};
use crate::loa::LOA;
use crate::module_loader::ModuleContext;
use tempfile::TempDir;
use std::sync::{Arc, Mutex};

#[test]
fn test_module_loa_enforcement_operator_success() {
    // Create a temporary canon store
    let temp_dir = TempDir::new().unwrap();
    let canon_store = Arc::new(Mutex::new(
        CanonStoreSled::new(temp_dir.path().to_str().unwrap()).unwrap()
    ));
    
    // Create runtime with Operator LOA
    let config = RuntimeConfig {
        enforcement_mode: EnforcementMode::Active,
        threshold: 0.5,
        active_model: None,
        telemetry_enabled: false,
        explanation_enabled: false,
    };
    
    let runtime = SigilRuntimeCore::new(LOA::Operator, canon_store, config).unwrap();
    
    // Test that Operator can execute hello module
    let module_context = ModuleContext {
        session_id: "test_session".to_string(),
        user_id: "test_user".to_string(),
        loa: LOA::Operator,
        input: "test_input".to_string(),
    };
    
    let module_registry = runtime.module_registry.lock().unwrap();
    let result = module_registry.run_module("hello", &module_context);
    
    assert!(result.is_ok(), "Operator LOA should be able to execute hello module");
    let output = result.unwrap();
    assert!(output.contains("Hello from Sigil!"), "Module should return expected greeting");
    assert!(output.contains("test_session"), "Module should include session ID");
    assert!(output.contains("test_user"), "Module should include user ID");
    assert!(output.contains("Operator"), "Module should include LOA level");
}

#[test]
fn test_module_loa_enforcement_guest_denied() {
    // Create a temporary canon store
    let temp_dir = TempDir::new().unwrap();
    let canon_store = Arc::new(Mutex::new(
        CanonStoreSled::new(temp_dir.path().to_str().unwrap()).unwrap()
    ));
    
    // Create runtime with Guest LOA
    let config = RuntimeConfig {
        enforcement_mode: EnforcementMode::Active,
        threshold: 0.5,
        active_model: None,
        telemetry_enabled: false,
        explanation_enabled: false,
    };
    
    let runtime = SigilRuntimeCore::new(LOA::Guest, canon_store, config).unwrap();
    
    // Test that Guest is denied access to hello module
    let module_context = ModuleContext {
        session_id: "test_session".to_string(),
        user_id: "test_user".to_string(),
        loa: LOA::Guest,
        input: "test_input".to_string(),
    };
    
    let module_registry = runtime.module_registry.lock().unwrap();
    let result = module_registry.run_module("hello", &module_context);
    
    assert!(result.is_err(), "Guest LOA should be denied access to hello module");
    
    let error = result.unwrap_err();
    match error {
        crate::errors::SigilError::InsufficientLoa { required, actual } => {
            assert_eq!(required, LOA::Operator, "Module should require Operator LOA");
            assert_eq!(actual, LOA::Guest, "Context should have Guest LOA");
        }
        _ => panic!("Expected InsufficientLoa error, got: {:?}", error),
    }
}

#[test]
fn test_module_registry_nonexistent_module() {
    // Create a temporary canon store
    let temp_dir = TempDir::new().unwrap();
    let canon_store = Arc::new(Mutex::new(
        CanonStoreSled::new(temp_dir.path().to_str().unwrap()).unwrap()
    ));
    
    let config = RuntimeConfig {
        enforcement_mode: EnforcementMode::Active,
        threshold: 0.5,
        active_model: None,
        telemetry_enabled: false,
        explanation_enabled: false,
    };
    
    let runtime = SigilRuntimeCore::new(LOA::Operator, canon_store, config).unwrap();
    
    // Test that nonexistent module returns not found error
    let module_context = ModuleContext {
        session_id: "test_session".to_string(),
        user_id: "test_user".to_string(),
        loa: LOA::Operator,
        input: "test_input".to_string(),
    };
    
    let module_registry = runtime.module_registry.lock().unwrap();
    let result = module_registry.run_module("nonexistent", &module_context);
    
    assert!(result.is_err(), "Nonexistent module should return error");
    
    let error = result.unwrap_err();
    match error {
        crate::errors::SigilError::Internal { message } => {
            assert!(message.contains("not found"), "Should be a 'not found' error");
        }
        _ => panic!("Expected Internal error for not found, got: {:?}", error),
    }
}

#[test]
fn test_module_registry_builtin_modules() {
    // Create a temporary canon store
    let temp_dir = TempDir::new().unwrap();
    let canon_store = Arc::new(Mutex::new(
        CanonStoreSled::new(temp_dir.path().to_str().unwrap()).unwrap()
    ));
    
    let config = RuntimeConfig {
        enforcement_mode: EnforcementMode::Active,
        threshold: 0.5,
        active_model: None,
        telemetry_enabled: false,
        explanation_enabled: false,
    };
    
    let runtime = SigilRuntimeCore::new(LOA::Root, canon_store, config).unwrap();
    
    // Test that hello module is registered by default
    let module_registry = runtime.module_registry.lock().unwrap();
    let hello_module = module_registry.get_module("hello");
    
    assert!(hello_module.is_some(), "Hello module should be registered by default");
    assert_eq!(hello_module.unwrap().required_loa(), LOA::Operator, "Hello module should require Operator LOA");
}
