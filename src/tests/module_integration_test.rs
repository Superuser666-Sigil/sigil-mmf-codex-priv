//! Integration tests for the module HTTP endpoint
//!
//! Tests the acceptance criteria for Track D1:
//! - Operator LOA → 200 with content
//! - Guest → 403

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::http::StatusCode;
use std::sync::{Arc, RwLock};
use tower::ServiceExt;

use crate::canon_store_sled_encrypted::CanonStoreSled as EncryptedCanonStoreSled;
use crate::keys::KeyManager;
use crate::loa::LOA;
use crate::runtime_config::{EnforcementMode, RuntimeConfig};
use crate::sigil_runtime_core::SigilRuntimeCore;
use crate::sigilweb::{ModuleRunRequest, add_trust_routes};
use std::sync::Mutex;
use tempfile::TempDir;

async fn create_test_app(loa: LOA) -> Router {
    // Create a temporary canon store
    let temp_dir = TempDir::new().unwrap();
    let encryption_key = KeyManager::dev_key_for_testing().unwrap();
    let canon_store = Arc::new(Mutex::new(
        EncryptedCanonStoreSled::new(temp_dir.path().to_str().unwrap(), &encryption_key).unwrap(),
    ));

    // Create runtime with specified LOA
    let config = RuntimeConfig {
        enforcement_mode: EnforcementMode::Active,
        threshold: 0.5,
        active_model: None,
        telemetry_enabled: false,
        explanation_enabled: false,
        model_refresh_from_canon: false,
    };

    let runtime = Arc::new(RwLock::new(
        SigilRuntimeCore::new(loa, canon_store, config).unwrap(),
    ));

    // Create the router with trust routes
    let router = Router::new();
    add_trust_routes(router, runtime)
}

fn create_module_request() -> ModuleRunRequest {
    ModuleRunRequest {
        input: "test input".to_string(),
        session_id: "test_session".to_string(),
        user_id: "test_user".to_string(),
    }
}

#[tokio::test]
async fn test_module_endpoint_operator_success() {
    let app = create_test_app(LOA::Operator).await;

    let request_body = serde_json::to_string(&create_module_request()).unwrap();

    let request = Request::builder()
        .method("POST")
        .uri("/api/module/hello/run")
        .header("content-type", "application/json")
        .body(Body::from(request_body))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_text = String::from_utf8(body.to_vec()).unwrap();

    // Should succeed with 200
    assert_eq!(
        status,
        StatusCode::OK,
        "Operator should get 200, got {}: {}",
        status,
        response_text
    );

    // Should contain the module output
    assert!(
        response_text.contains("Hello from Sigil!"),
        "Response should contain module output"
    );
    assert!(
        response_text.contains("test_session"),
        "Response should contain session ID"
    );
    assert!(
        response_text.contains("test_user"),
        "Response should contain user ID"
    );
}

#[tokio::test]
async fn test_module_endpoint_guest_forbidden() {
    let app = create_test_app(LOA::Guest).await;

    let request_body = serde_json::to_string(&create_module_request()).unwrap();

    let request = Request::builder()
        .method("POST")
        .uri("/api/module/hello/run")
        .header("content-type", "application/json")
        .body(Body::from(request_body))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_text = String::from_utf8(body.to_vec()).unwrap();

    // Should be forbidden with 403
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "Guest should get 403, got {}: {}",
        status,
        response_text
    );

    // Should contain LOA-related error message
    assert!(
        response_text.contains("Insufficient LOA")
            || response_text.contains("forbidden")
            || response_text.contains("denied by trust evaluation"),
        "Response should indicate insufficient privileges: {}",
        response_text
    );
}

#[tokio::test]
async fn test_module_endpoint_nonexistent_module() {
    let app = create_test_app(LOA::Root).await;

    let request_body = serde_json::to_string(&create_module_request()).unwrap();

    let request = Request::builder()
        .method("POST")
        .uri("/api/module/nonexistent/run")
        .header("content-type", "application/json")
        .body(Body::from(request_body))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    // Should be not found with 404
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_text = String::from_utf8(body.to_vec()).unwrap();

    // Should contain not found error
    assert!(
        response_text.contains("not found"),
        "Response should indicate module not found: {}",
        response_text
    );
}
