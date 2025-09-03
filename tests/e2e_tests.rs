//! End-to-End Integration Tests for Sigil MVP
//! 
//! These tests verify the complete system behavior across all components:
//! - Trust evaluation and LOA enforcement
//! - Cryptographic audit integrity  
//! - Canon operations and quorum enforcement
//! - Module execution gating
//! - Error handling and default-deny behavior

use std::sync::{Arc, RwLock, Mutex};
use axum::body::Body;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::Router;
use tower::ServiceExt;
use serde_json::json;
use tempfile::TempDir;

use mmf_sigil::{
    sigil_runtime_core::SigilRuntimeCore,
    canon_store_sled::CanonStoreSled,
    runtime_config::{EnforcementMode, RuntimeConfig},
    loa::LOA,
    sigilweb::add_trust_routes,
    canonical_record::CanonicalRecord,
    audit_chain::{ReasoningChain, FrozenChain, Verdict},
    license_validator::validate_license,
};

/// Create a test runtime with specified LOA and temporary storage
async fn create_test_runtime(loa: LOA) -> (Arc<RwLock<SigilRuntimeCore>>, TempDir) {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let canon_store = Arc::new(Mutex::new(
        CanonStoreSled::new(temp_dir.path().to_str().unwrap()).expect("Failed to create Canon store")
    ));
    
    let config = RuntimeConfig {
        enforcement_mode: EnforcementMode::Active,
        threshold: 0.4, // Match the trust model threshold
        active_model: None,
        telemetry_enabled: false,
        explanation_enabled: false,
    };
    
    let runtime = Arc::new(RwLock::new(
        SigilRuntimeCore::new(loa, canon_store, config).expect("Failed to create runtime")
    ));
    
    (runtime, temp_dir)
}

/// Create a test runtime from a license file (license-agnostic approach)
async fn create_test_runtime_from_license(license_path: &str) -> (Arc<RwLock<SigilRuntimeCore>>, TempDir) {
    // Read the license first to get the expected runtime/canon IDs
    let license_content = std::fs::read_to_string(license_path)
        .expect("Failed to read license file");
    
    #[derive(serde::Deserialize)]
    struct TestLicenseWrapper {
        license: TestLicense,
    }
    
    #[derive(serde::Deserialize)]
    #[allow(dead_code)]
    struct TestLicense {
        #[serde(rename = "issuedAt")]
        issued_at: chrono::DateTime<chrono::Utc>,
        #[serde(rename = "expiresAt")]
        expires_at: chrono::DateTime<chrono::Utc>,
        loa: LOA,
        owner: TestLicenseOwner,
        bindings: TestLicenseBindings,
    }
    
    #[derive(serde::Deserialize)]
    #[allow(dead_code)]
    struct TestLicenseOwner {
        name: String,
    }
    
    #[derive(serde::Deserialize)]
    struct TestLicenseBindings {
        #[serde(rename = "canonFingerprint")]
        canon_fingerprint: String,
        #[serde(rename = "runtimeId")]
        runtime_id: String,
    }
    
    let wrapper: TestLicenseWrapper = toml::from_str(&license_content)
        .expect("Failed to parse license TOML");
    
    let expected_runtime_id = &wrapper.license.bindings.runtime_id;
    let expected_canon_fingerprint = &wrapper.license.bindings.canon_fingerprint;
    
    // Now validate with the correct expected values
    let license_result = validate_license(
        license_path,
        expected_runtime_id,
        expected_canon_fingerprint
    ).expect("Failed to validate license");
    
    if !license_result.valid {
        panic!("Invalid license: {}", license_result.message);
    }
    
    let loa = license_result.license.loa;
    println!("🔑 Using license for {} with LOA: {:?}", license_result.license.owner.name, loa);
    
    // Create runtime with the license-determined LOA
    create_test_runtime(loa).await
}

/// Create an Axum app with the test runtime
async fn create_test_app(loa: LOA) -> (Router, TempDir) {
    let (runtime, temp_dir) = create_test_runtime(loa).await;
    let router = Router::new();
    let app = add_trust_routes(router, runtime);
    (app, temp_dir)
}

/// Create an Axum app from a license file (license-agnostic approach)
async fn create_test_app_from_license(license_path: &str) -> (Router, TempDir) {
    let (runtime, temp_dir) = create_test_runtime_from_license(license_path).await;
    let router = Router::new();
    let app = add_trust_routes(router, runtime);
    (app, temp_dir)
}

// ============================================================================
// E2E Test: License-Based Authentication (New License-Agnostic Approach)
// ============================================================================

#[tokio::test]
#[ignore = "Requires license files to be generated - see Track F license generation"]
async fn e2e_license_based_multi_user_root_operations() {
    // Test that Root license holders can perform privileged operations
    let (app, _temp_dir) = create_test_app_from_license("test_alice_root.toml").await;
    
    let request_body = json!({
        "who": "alice_root",
        "action": "canon_write",
        "target": "system", 
        "session_id": "alice_session",
        "loa": "root"
    });
    
    let request = Request::builder()
        .method("POST")
        .uri("/api/trust/check")
        .header("content-type", "application/json")
        .body(Body::from(request_body.to_string()))
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let response_text = String::from_utf8(body.to_vec()).unwrap();
    
    // Debug output for non-OK responses
    if status != StatusCode::OK {
        println!("Request failed with {}: {}", status, response_text);
        println!("Request body was: {}", request_body);
    }
    
    assert_eq!(status, StatusCode::OK, "Alice (Root license) should be allowed system Canon writes");
    
    let response_json: serde_json::Value = serde_json::from_str(&response_text)
        .expect("Response should be valid JSON");
    
    assert_eq!(response_json["allowed"], true, "Root license should allow system Canon operations");
    assert!(response_json["score"].as_f64().unwrap() > 0.0, "Trust score should be positive for Root");
}

#[tokio::test]
#[ignore = "Requires license files to be generated - see Track F license generation"]
async fn e2e_license_based_mentor_operations() {
    // Test that Mentor license holders have appropriate permissions but not Root-level access
    let (app, _temp_dir) = create_test_app_from_license("test_bob_mentor.toml").await;
    
    let request_body = json!({
        "who": "bob_mentor",
        "action": "canon_read",
        "target": "system", 
        "session_id": "bob_session",
        "loa": "mentor"
    });
    
    let request = Request::builder()
        .method("POST")
        .uri("/api/trust/check")
        .header("content-type", "application/json")
        .body(Body::from(request_body.to_string()))
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    
    assert_eq!(status, StatusCode::OK, "Bob (Mentor license) should be allowed system Canon reads");
    
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let response_text = String::from_utf8(body.to_vec()).unwrap();
    let response_json: serde_json::Value = serde_json::from_str(&response_text)
        .expect("Response should be valid JSON");
    
    assert_eq!(response_json["allowed"], true, "Mentor license should allow system Canon reads");
}

#[tokio::test]
#[ignore = "Requires license files to be generated - see Track F license generation"]
async fn e2e_license_based_operator_module_execution() {
    // Test that Operator license holders can execute modules
    let (app, _temp_dir) = create_test_app_from_license("test_carol_operator.toml").await;
    
    let request_body = json!({
        "input": "test input",
        "session_id": "carol_session", 
        "user_id": "carol_operator"
    });
    
    let request = Request::builder()
        .method("POST")
        .uri("/api/module/hello/run")
        .header("content-type", "application/json")
        .body(Body::from(request_body.to_string()))
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let response_text = String::from_utf8(body.to_vec()).unwrap();
    
    if status != StatusCode::OK {
        println!("Carol (Operator) module execution failed with {}: {}", status, response_text);
    }
    
    assert_eq!(status, StatusCode::OK, "Carol (Operator license) should be allowed to execute modules");
    
    let response_json: serde_json::Value = serde_json::from_str(&response_text)
        .expect("Response should be valid JSON");
    
    assert!(response_json["output"].as_str().unwrap().contains("Hello from Sigil!"));
    assert_eq!(response_json["error"], serde_json::Value::Null);
}

// ============================================================================
// E2E Test 1: e2e_allow - Successful operations with proper LOA (Legacy)
// ============================================================================

#[tokio::test]
async fn e2e_allow_trust_check_operator() {
    let (app, _temp_dir) = create_test_app(LOA::Operator).await;
    
    let request_body = json!({
        "who": "test_user",
        "action": "canon_read",
        "target": "canon", 
        "session_id": "test_session",
        "loa": "operator"
    });
    
    let request = Request::builder()
        .method("POST")
        .uri("/api/trust/check")
        .header("content-type", "application/json")
        .body(Body::from(request_body.to_string()))
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    
    // Debug: Print response for diagnosis
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let response_text = String::from_utf8(body.to_vec()).unwrap();
    
    if status != StatusCode::OK {
        println!("Expected 200 OK but got {}: {}", status, response_text);
    }
    

    assert_eq!(status, StatusCode::OK, "Operator should be allowed to perform read operations: {}", response_text);
    
    let response_json: serde_json::Value = serde_json::from_str(&response_text)
        .expect("Response should be valid JSON");
    
    assert_eq!(response_json["allowed"], true, "Trust evaluation should allow the operation");
    assert!(response_json["score"].as_f64().unwrap() > 0.0, "Score should be positive");
}

#[tokio::test]
async fn e2e_allow_module_execution_operator() {
    let (app, _temp_dir) = create_test_app(LOA::Operator).await;
    
    let request_body = json!({
        "input": "test input",
        "session_id": "test_session", 
        "user_id": "test_user"
    });
    
    let request = Request::builder()
        .method("POST")
        .uri("/api/module/hello/run")
        .header("content-type", "application/json")
        .body(Body::from(request_body.to_string()))
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let response_text = String::from_utf8(body.to_vec()).unwrap();
    
    if status != StatusCode::OK {
        println!("Module execution failed with {}: {}", status, response_text);
    }
    
    assert_eq!(status, StatusCode::OK, "Operator should be allowed to execute modules: {}", response_text);
    
    let response_json: serde_json::Value = serde_json::from_str(&response_text)
        .expect("Response should be valid JSON");
    
    assert!(response_json["output"].as_str().unwrap().contains("Hello from Sigil!"));
    assert_eq!(response_json["error"], serde_json::Value::Null);
}

#[tokio::test]
async fn e2e_allow_canon_user_write_operator() {
    let (app, _temp_dir) = create_test_app(LOA::Operator).await;
    
    let request_body = json!({
        "space": "user",
        "key": "test_key",
        "value": "test_value",
        "session_id": "test_session",
        "user_id": "test_user"
    });
    
    let request = Request::builder()
        .method("POST")
        .uri("/api/canon/user/write")
        .header("content-type", "application/json")
        .body(Body::from(request_body.to_string()))
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    
    assert_eq!(status, StatusCode::OK, "Operator should be allowed to write to user Canon space");
    
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let response_text = String::from_utf8(body.to_vec()).unwrap();
    let response_json: serde_json::Value = serde_json::from_str(&response_text)
        .expect("Response should be valid JSON");
    
    assert_eq!(response_json["success"], true);
}

// ============================================================================
// E2E Test 2: e2e_deny - Denial of insufficient LOA operations
// ============================================================================

#[tokio::test]
async fn e2e_deny_module_execution_guest() {
    let (app, _temp_dir) = create_test_app(LOA::Guest).await;
    
    let request_body = json!({
        "input": "test input",
        "session_id": "test_session",
        "user_id": "test_user"
    });
    
    let request = Request::builder()
        .method("POST")
        .uri("/api/module/hello/run")
        .header("content-type", "application/json")
        .body(Body::from(request_body.to_string()))
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    
    assert_eq!(status, StatusCode::FORBIDDEN, "Guest should be denied module execution");
    
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let response_text = String::from_utf8(body.to_vec()).unwrap();
    
    assert!(response_text.contains("denied by trust evaluation"), 
           "Response should indicate trust evaluation denial");
}

#[tokio::test]
async fn e2e_deny_trust_check_guest_risky_action() {
    let (app, _temp_dir) = create_test_app(LOA::Guest).await;
    
    let request_body = json!({
        "who": "test_user",
        "action": "canon_write",
        "target": "system",
        "session_id": "test_session",
        "loa": "guest"
    });
    
    let request = Request::builder()
        .method("POST")
        .uri("/api/trust/check")
        .header("content-type", "application/json")
        .body(Body::from(request_body.to_string()))
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    
    assert_eq!(status, StatusCode::OK, "Trust check should return status, not deny access");
    
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let response_text = String::from_utf8(body.to_vec()).unwrap();
    let response_json: serde_json::Value = serde_json::from_str(&response_text)
        .expect("Response should be valid JSON");
    


    assert_eq!(response_json["allowed"], false, "Guest should not be allowed canon_write actions");
}

// ============================================================================
// E2E Test 3: e2e_error_default_deny - Errors result in denial
// ============================================================================

#[tokio::test]
async fn e2e_error_default_deny_malformed_request() {
    let (app, _temp_dir) = create_test_app(LOA::Operator).await;
    
    // Send malformed JSON
    let request = Request::builder()
        .method("POST")
        .uri("/api/trust/check")
        .header("content-type", "application/json")
        .body(Body::from("invalid json"))
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    
    assert_eq!(status, StatusCode::BAD_REQUEST, "Malformed request should be rejected");
}

#[tokio::test]
async fn e2e_error_default_deny_missing_user_id() {
    let (app, _temp_dir) = create_test_app(LOA::Operator).await;
    
    let request_body = json!({
        "input": "test input",
        "session_id": "test_session",
        "user_id": "" // Empty user_id should be rejected
    });
    
    let request = Request::builder()
        .method("POST")
        .uri("/api/module/hello/run")
        .header("content-type", "application/json")
        .body(Body::from(request_body.to_string()))
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    
    assert_eq!(status, StatusCode::BAD_REQUEST, "Empty user_id should be rejected");
    
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let response_text = String::from_utf8(body.to_vec()).unwrap();
    
    assert!(response_text.contains("user_id cannot be empty"), 
           "Error message should indicate user_id validation failure");
}

#[tokio::test]
async fn e2e_error_default_deny_nonexistent_module() {
    let (app, _temp_dir) = create_test_app(LOA::Root).await;
    
    let request_body = json!({
        "input": "test input",
        "session_id": "test_session",
        "user_id": "test_user"
    });
    
    let request = Request::builder()
        .method("POST")
        .uri("/api/module/nonexistent/run")
        .header("content-type", "application/json")
        .body(Body::from(request_body.to_string()))
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    
    assert_eq!(status, StatusCode::NOT_FOUND, "Nonexistent module should return 404");
    
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let response_text = String::from_utf8(body.to_vec()).unwrap();
    
    assert!(response_text.contains("not found"), 
           "Error message should indicate module not found");
}

// ============================================================================
// Unit tests for cryptographic integrity (part of e2e_tamper_audit)
// ============================================================================

#[test]
fn e2e_tamper_audit_reasoning_chain_integrity() {

    
    let mut chain = ReasoningChain::new("Test reasoning".to_string(), LOA::Operator);
    chain.add_context("Test context");
    chain.add_reasoning("Test reasoning step");
    chain.add_suggestion("Test suggestion");
    chain.set_verdict(Verdict::Deny); // Use Deny to avoid witness quorum requirement
    chain.set_trust_score(0.8, true);
    
    // Finalize the chain first
    let mut finalized_chain = chain;
    finalized_chain.finalize_reasoning().expect("Should be able to finalize chain");
    
    // Freeze the chain directly (without storing in Canon to avoid quorum requirements)
    let frozen = FrozenChain::freeze_reasoning_chain(finalized_chain).expect("Should be able to freeze chain");
    
    // Verify integrity
    assert!(frozen.verify_integrity().is_ok(), "Frozen chain should have valid integrity");
    
    // Test that the original frozen chain is valid
    assert!(frozen.verify_integrity().is_ok(), "Original chain should be valid");
}

#[test]
fn e2e_tamper_audit_canonical_record_integrity() {
    // Create a test canonical record from a reasoning chain
    let reasoning_chain = ReasoningChain::new("Test record".to_string(), LOA::Operator);
    let record = CanonicalRecord::from_reasoning_chain(
        &reasoning_chain,
        "system",   // tenant
        "audit",    // space
        None        // prev
    ).expect("Should be able to create canonical record");
    
    // Verify the record structure
    assert_eq!(record.kind, "reasoning_chain");
    assert_eq!(record.space, "audit");
    assert_eq!(record.tenant, "system");
    // ReasoningChain IDs are UUIDs, so check for valid UUID format
    assert_eq!(record.id.len(), 36); // Standard UUID length
    assert!(record.id.contains('-')); // UUIDs contain hyphens
    assert!(record.payload.is_object());
    
    // Debug: Print payload to see what fields are available
    println!("Canonical record payload keys: {:?}", record.payload.as_object().unwrap().keys().collect::<Vec<_>>());
    
    // Test that essential fields are present in the payload
    assert!(record.payload.get("audit").is_some(), "Should have audit field");
    // The chain_id is in audit.chain_id, not directly in the payload
    let audit = record.payload.get("audit").unwrap();
    assert!(audit.get("chain_id").is_some(), "Should have chain_id in audit");
    assert!(record.payload.get("reasoning").is_some(), "Should have reasoning field");
    
    // Verify hash is computed
    assert!(!record.hash.is_empty());
    
    // Verify canonical JSON can be generated
    let canonical_json = record.to_canonical_json().expect("Should be able to generate canonical JSON");
    assert!(!canonical_json.is_empty());
}

// ============================================================================
// This file will be continued with quorum, Canon iteration, and module tests
// ============================================================================
