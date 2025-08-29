// tests/web.rs
use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use mmf_sigil::sigilweb::{build_trust_router, TrustCheckRequest};
use mmf_sigil::sigil_runtime_core::SigilRuntimeCore;
use mmf_sigil::canon_store_sled::CanonStoreSled;
use mmf_sigil::loa::LOA;
use mmf_sigil::irl_modes::IRLConfig;
use std::sync::Mutex;
use serde_json::json;
use std::sync::{Arc, RwLock};
use tower::ServiceExt; // for .oneshot()

#[tokio::test]
async fn trust_check_returns_200_on_valid_payload() {
    // Create an in-memory Canon store for the runtime
    let temp_dir = tempfile::tempdir().expect("temp dir should be created");
    let path = temp_dir.path().to_str().unwrap();
    let store = CanonStoreSled::new(path).expect("should create canon store");
    let core = SigilRuntimeCore::new(LOA::Observer, Arc::new(Mutex::new(store)), IRLConfig::default()).expect("runtime init");
    let core = Arc::new(RwLock::new(core));
    let app: Router = build_trust_router(core);

    let payload = TrustCheckRequest {
        who: "tester".to_string(),
        action: "access".to_string(),
        target: None,
        session_id: "unit".to_string(),
        loa: "root".to_string(),
    };

    let req = Request::builder()
        .uri("/trust/check")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(&payload).unwrap()))
        .unwrap();

    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn trust_check_rejects_malformed_loa() {
    let temp_dir = tempfile::tempdir().expect("temp dir should be created");
    let path = temp_dir.path().to_str().unwrap();
    let store = CanonStoreSled::new(path).expect("should create canon store");
    let core = SigilRuntimeCore::new(LOA::Observer, Arc::new(Mutex::new(store)), IRLConfig::default()).expect("runtime init");
    let core = Arc::new(RwLock::new(core));
    let app = build_trust_router(core);

    let bad_payload = json!({
        "who": "x",
        "action": "do",
        "target": null,
        "session_id": "u",
        "loa": "INVALID"
    });

    let req = Request::builder()
        .uri("/trust/check")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(bad_payload.to_string()))
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    // Expect a 400 BadRequest due to invalid LOA
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let json_val: serde_json::Value = serde_json::from_slice(&body).unwrap();
    // The new API includes an error field; ensure it is present
    assert!(json_val.get("error").is_some());
}