//! Comprehensive tests for module execution runtime
//!
//! Tests all aspects of the module execution system:
//! - Module registration and lifecycle
//! - LOA enforcement across all levels
//! - Error handling and edge cases
//! - Module isolation and security
//! - Performance and resource management

use crate::canon_store_sled_encrypted::CanonStoreSled as EncryptedCanonStoreSled;
use crate::errors::{SigilError, SigilResult};
use crate::keys::KeyManager;
use crate::loa::LOA;
use crate::module_loader::{ModuleContext, SigilModule};
use crate::runtime_config::{EnforcementMode, RuntimeConfig};
use crate::sigil_runtime_core::SigilRuntimeCore;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

/// Test module that requires different LOA levels
struct TestModule {
    required_loa: LOA,
    output_prefix: String,
}

impl TestModule {
    fn new(required_loa: LOA, output_prefix: &str) -> Self {
        Self {
            required_loa,
            output_prefix: output_prefix.to_string(),
        }
    }
}

impl SigilModule for TestModule {
    fn required_loa(&self) -> LOA {
        self.required_loa.clone()
    }

    fn run(&self, ctx: &ModuleContext) -> SigilResult<String> {
        Ok(format!(
            "{}: Executed with LOA {:?} for user {} in session {}",
            self.output_prefix, ctx.loa, ctx.user_id, ctx.session_id
        ))
    }
}

/// Module that simulates resource-intensive operations
struct ResourceIntensiveModule;

impl SigilModule for ResourceIntensiveModule {
    fn required_loa(&self) -> LOA {
        LOA::Mentor
    }

    fn run(&self, ctx: &ModuleContext) -> SigilResult<String> {
        // Simulate some work
        let iterations = ctx.input.parse::<usize>().unwrap_or(1000);
        let mut sum = 0u64;
        for i in 0..iterations {
            sum = sum.wrapping_add(i as u64);
        }
        Ok(format!(
            "Resource-intensive module completed {} iterations, result: {}",
            iterations, sum
        ))
    }
}

/// Module that can fail in different ways
struct FallibleModule;

impl SigilModule for FallibleModule {
    fn required_loa(&self) -> LOA {
        LOA::Observer
    }

    fn run(&self, ctx: &ModuleContext) -> SigilResult<String> {
        match ctx.input.as_str() {
            "fail" => Err(SigilError::Internal {
                message: "Module intentionally failed".to_string(),
            }),
            "panic" => panic!("Module panic for testing"),
            "invalid_input" => Err(SigilError::Validation {
                field: "input".to_string(),
                message: "Invalid input provided".to_string(),
            }),
            _ => Ok(format!(
                "Fallible module succeeded with input: {}",
                ctx.input
            )),
        }
    }
}

#[test]
fn test_comprehensive_loa_enforcement() {
    let temp_dir = TempDir::new().unwrap();
    let encryption_key = KeyManager::dev_key_for_testing().unwrap();
    let canon_store = Arc::new(Mutex::new(
        EncryptedCanonStoreSled::new(temp_dir.path().to_str().unwrap(), &encryption_key).unwrap(),
    ));

    let config = RuntimeConfig {
        enforcement_mode: EnforcementMode::Active,
        threshold: 0.5,
        active_model: None,
        telemetry_enabled: false,
        explanation_enabled: false,
        model_refresh_from_canon: false,
    };

    let runtime = SigilRuntimeCore::new(LOA::Root, canon_store, config).unwrap();

    // Register test modules with different LOA requirements
    {
        let mut module_registry = runtime.module_registry.lock().unwrap();
        module_registry.register_module(
            "guest_module",
            Box::new(TestModule::new(LOA::Guest, "Guest")),
        );
        module_registry.register_module(
            "observer_module",
            Box::new(TestModule::new(LOA::Observer, "Observer")),
        );
        module_registry.register_module(
            "operator_module",
            Box::new(TestModule::new(LOA::Operator, "Operator")),
        );
        module_registry.register_module(
            "mentor_module",
            Box::new(TestModule::new(LOA::Mentor, "Mentor")),
        );
        module_registry
            .register_module("root_module", Box::new(TestModule::new(LOA::Root, "Root")));
    }

    // Test each LOA level access pattern
    let test_cases = vec![
        // (user_loa, module_name, should_succeed)
        (LOA::Guest, "guest_module", true),
        (LOA::Guest, "observer_module", false),
        (LOA::Guest, "operator_module", false),
        (LOA::Guest, "mentor_module", false),
        (LOA::Guest, "root_module", false),
        (LOA::Observer, "guest_module", true),
        (LOA::Observer, "observer_module", true),
        (LOA::Observer, "operator_module", false),
        (LOA::Observer, "mentor_module", false),
        (LOA::Observer, "root_module", false),
        (LOA::Operator, "guest_module", true),
        (LOA::Operator, "observer_module", true),
        (LOA::Operator, "operator_module", true),
        (LOA::Operator, "mentor_module", false),
        (LOA::Operator, "root_module", false),
        (LOA::Mentor, "guest_module", true),
        (LOA::Mentor, "observer_module", true),
        (LOA::Mentor, "operator_module", true),
        (LOA::Mentor, "mentor_module", true),
        (LOA::Mentor, "root_module", false),
        (LOA::Root, "guest_module", true),
        (LOA::Root, "observer_module", true),
        (LOA::Root, "operator_module", true),
        (LOA::Root, "mentor_module", true),
        (LOA::Root, "root_module", true),
    ];

    let module_registry = runtime.module_registry.lock().unwrap();

    for (user_loa, module_name, should_succeed) in test_cases {
        let context = ModuleContext {
            session_id: "test_session".to_string(),
            user_id: "test_user".to_string(),
            loa: user_loa.clone(),
            input: "test_input".to_string(),
        };

        let result = module_registry.run_module(module_name, &context);

        if should_succeed {
            assert!(
                result.is_ok(),
                "LOA {:?} should be able to execute {}",
                user_loa,
                module_name
            );
            let output = result.unwrap();
            assert!(
                output.contains(&format!("{:?}", user_loa)),
                "Output should contain user LOA level"
            );
        } else {
            assert!(
                result.is_err(),
                "LOA {:?} should NOT be able to execute {}",
                user_loa,
                module_name
            );
            match result.unwrap_err() {
                SigilError::InsufficientLoa { .. } => {
                    // Expected error type
                }
                other => panic!("Expected InsufficientLoa error, got: {:?}", other),
            }
        }
    }

    println!("✅ Comprehensive LOA enforcement test passed");
}

#[test]
fn test_module_error_handling() {
    let temp_dir = TempDir::new().unwrap();
    let encryption_key = KeyManager::dev_key_for_testing().unwrap();
    let canon_store = Arc::new(Mutex::new(
        EncryptedCanonStoreSled::new(temp_dir.path().to_str().unwrap(), &encryption_key).unwrap(),
    ));

    let config = RuntimeConfig {
        enforcement_mode: EnforcementMode::Active,
        threshold: 0.5,
        active_model: None,
        telemetry_enabled: false,
        explanation_enabled: false,
        model_refresh_from_canon: false,
    };

    let runtime = SigilRuntimeCore::new(LOA::Root, canon_store, config).unwrap();

    // Register fallible module
    {
        let mut module_registry = runtime.module_registry.lock().unwrap();
        module_registry.register_module("fallible", Box::new(FallibleModule));
    }

    let module_registry = runtime.module_registry.lock().unwrap();

    // Test different error conditions
    let error_cases = vec![
        ("fail", "Module intentionally failed"),
        ("invalid_input", "Invalid input provided"),
    ];

    for (input, expected_error) in error_cases {
        let context = ModuleContext {
            session_id: "error_test_session".to_string(),
            user_id: "error_test_user".to_string(),
            loa: LOA::Observer,
            input: input.to_string(),
        };

        let result = module_registry.run_module("fallible", &context);
        assert!(result.is_err(), "Module should fail with input: {}", input);

        let error_msg = format!("{:?}", result.unwrap_err());
        assert!(
            error_msg.contains(expected_error),
            "Error should contain expected message for input: {}",
            input
        );
    }

    // Test successful execution
    let success_context = ModuleContext {
        session_id: "success_session".to_string(),
        user_id: "success_user".to_string(),
        loa: LOA::Observer,
        input: "success".to_string(),
    };

    let result = module_registry.run_module("fallible", &success_context);
    assert!(result.is_ok(), "Module should succeed with valid input");
    assert!(
        result.unwrap().contains("succeeded"),
        "Should contain success message"
    );

    println!("✅ Module error handling test passed");
}

#[test]
fn test_module_registry_management() {
    let temp_dir = TempDir::new().unwrap();
    let encryption_key = KeyManager::dev_key_for_testing().unwrap();
    let canon_store = Arc::new(Mutex::new(
        EncryptedCanonStoreSled::new(temp_dir.path().to_str().unwrap(), &encryption_key).unwrap(),
    ));

    let config = RuntimeConfig {
        enforcement_mode: EnforcementMode::Active,
        threshold: 0.5,
        active_model: None,
        telemetry_enabled: false,
        explanation_enabled: false,
        model_refresh_from_canon: false,
    };

    let runtime = SigilRuntimeCore::new(LOA::Root, canon_store, config).unwrap();

    {
        let mut module_registry = runtime.module_registry.lock().unwrap();

        // Test module registration
        module_registry.register_module("test1", Box::new(TestModule::new(LOA::Guest, "Test1")));
        module_registry.register_module("test2", Box::new(TestModule::new(LOA::Operator, "Test2")));

        // Test module retrieval
        assert!(
            module_registry.get_module("test1").is_some(),
            "Should find registered module test1"
        );
        assert!(
            module_registry.get_module("test2").is_some(),
            "Should find registered module test2"
        );
        assert!(
            module_registry.get_module("nonexistent").is_none(),
            "Should not find nonexistent module"
        );

        // Test built-in module exists
        assert!(
            module_registry.get_module("hello").is_some(),
            "Should have built-in hello module"
        );

        // Test module overwriting
        module_registry.register_module(
            "test1",
            Box::new(TestModule::new(LOA::Root, "Test1Updated")),
        );
        let updated_module = module_registry.get_module("test1").unwrap();
        assert_eq!(
            updated_module.required_loa(),
            LOA::Root,
            "Module should be updated"
        );
    }

    println!("✅ Module registry management test passed");
}

#[test]
fn test_module_context_validation() {
    let temp_dir = TempDir::new().unwrap();
    let encryption_key = KeyManager::dev_key_for_testing().unwrap();
    let canon_store = Arc::new(Mutex::new(
        EncryptedCanonStoreSled::new(temp_dir.path().to_str().unwrap(), &encryption_key).unwrap(),
    ));

    let config = RuntimeConfig {
        enforcement_mode: EnforcementMode::Active,
        threshold: 0.5,
        active_model: None,
        telemetry_enabled: false,
        explanation_enabled: false,
        model_refresh_from_canon: false,
    };

    let runtime = SigilRuntimeCore::new(LOA::Root, canon_store, config).unwrap();

    {
        let mut module_registry = runtime.module_registry.lock().unwrap();
        module_registry.register_module("resource_intensive", Box::new(ResourceIntensiveModule));
    }

    let module_registry = runtime.module_registry.lock().unwrap();

    // Test context with different inputs
    let test_inputs = vec![
        ("100", true),     // Valid number
        ("5000", true),    // Larger number
        ("invalid", true), // Invalid number (uses default)
        ("0", true),       // Edge case
    ];

    for (input, should_succeed) in test_inputs {
        let context = ModuleContext {
            session_id: format!("session_{}", input),
            user_id: format!("user_{}", input),
            loa: LOA::Mentor,
            input: input.to_string(),
        };

        let result = module_registry.run_module("resource_intensive", &context);

        if should_succeed {
            assert!(result.is_ok(), "Module should handle input: {}", input);
            let output = result.unwrap();
            assert!(
                output.contains("completed"),
                "Should contain completion message"
            );
        }
    }

    println!("✅ Module context validation test passed");
}

#[test]
fn test_module_isolation() {
    // Test that modules don't interfere with each other
    let temp_dir = TempDir::new().unwrap();
    let encryption_key = KeyManager::dev_key_for_testing().unwrap();
    let canon_store = Arc::new(Mutex::new(
        EncryptedCanonStoreSled::new(temp_dir.path().to_str().unwrap(), &encryption_key).unwrap(),
    ));

    let config = RuntimeConfig {
        enforcement_mode: EnforcementMode::Active,
        threshold: 0.5,
        active_model: None,
        telemetry_enabled: false,
        explanation_enabled: false,
        model_refresh_from_canon: false,
    };

    let runtime = SigilRuntimeCore::new(LOA::Root, canon_store, config).unwrap();

    {
        let mut module_registry = runtime.module_registry.lock().unwrap();
        module_registry
            .register_module("module_a", Box::new(TestModule::new(LOA::Guest, "ModuleA")));
        module_registry
            .register_module("module_b", Box::new(TestModule::new(LOA::Guest, "ModuleB")));
    }

    let module_registry = runtime.module_registry.lock().unwrap();

    // Run modules concurrently (simulated)
    let contexts = [
        ModuleContext {
            session_id: "session_a".to_string(),
            user_id: "user_a".to_string(),
            loa: LOA::Guest,
            input: "input_a".to_string(),
        },
        ModuleContext {
            session_id: "session_b".to_string(),
            user_id: "user_b".to_string(),
            loa: LOA::Guest,
            input: "input_b".to_string(),
        },
    ];

    let results: Vec<_> = contexts
        .iter()
        .enumerate()
        .map(|(i, ctx)| {
            let module_name = if i % 2 == 0 { "module_a" } else { "module_b" };
            module_registry.run_module(module_name, ctx)
        })
        .collect();

    // Verify all executions succeeded and produced correct outputs
    for (i, result) in results.iter().enumerate() {
        assert!(result.is_ok(), "Module execution {} should succeed", i);
        let output = result.as_ref().unwrap();

        if i % 2 == 0 {
            assert!(output.contains("ModuleA"), "Should contain ModuleA output");
            assert!(output.contains("user_a"), "Should contain correct user ID");
        } else {
            assert!(output.contains("ModuleB"), "Should contain ModuleB output");
            assert!(output.contains("user_b"), "Should contain correct user ID");
        }
    }

    println!("✅ Module isolation test passed");
}
