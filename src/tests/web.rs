// tests/web.rs
use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use mmf_sigil::sigilweb::{build_trust_router, TrustCheckRequest};
use mmf_sigil::sigil_runtime_core::SigilRuntimeCore;
use serde_json::json;
use std::sync::{Arc, RwLock};
use tower::ServiceExt; // for .oneshot()

#[tokio::test]
async fn trust_check_returns_200_on_valid_payload() {
    let core = Arc::new(RwLock::new(SigilRuntimeCore::new()));
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
    let core = Arc::new(RwLock::new(SigilRuntimeCore::new()));
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
    assert_eq!(response.status(), StatusCode::OK); // still 200, but body indicates failure

    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let json_val: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json_val["success"], false);
    assert_eq!(json_val["result"]["allowed"], false);
}