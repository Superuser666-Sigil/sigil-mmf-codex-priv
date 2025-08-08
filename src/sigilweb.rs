use crate::audit::AuditEvent;
use crate::loa::LOA;
use crate::sigil_runtime_core::SigilRuntimeCore;
use axum::{
    extract::Extension,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::{Arc, RwLock};

#[derive(Debug, Deserialize)]
pub struct TrustCheckRequest {
    who: String,
    action: String,
    target: Option<String>,
    session_id: String,
    loa: String,
}

#[derive(Debug, Serialize)]
pub struct TrustCheckResponse {
    allowed: bool,
    score: f64,
    model_id: Option<String>,
    threshold: Option<f64>,
}

// Add trust-related routes
pub fn add_trust_routes(router: Router, runtime: Arc<RwLock<SigilRuntimeCore>>) -> Router {
    router
        .route("/api/trust/check", post(check_trust))
        .route("/api/trust/status", get(trust_status))
        .layer(Extension(runtime))
}

/// Build a minimal router exposing trust endpoints, versioned alias, and health checks
pub fn build_trust_router(runtime: Arc<RwLock<SigilRuntimeCore>>) -> Router {
    let router = Router::new()
        // current endpoints
        .route("/api/trust/check", post(check_trust))
        .route("/api/trust/status", get(trust_status))
        // versioned aliases
        .route("/v1/trust/check", post(check_trust))
        .route("/v1/trust/status", get(trust_status))
        // backward-compatible aliases used by some tests
        .route("/trust/check", post(check_trust))
        .route("/trust/status", get(trust_status))
        // health endpoints
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .layer(Extension(runtime));

    router
}

#[axum::debug_handler]
async fn check_trust(
    Extension(runtime): Extension<Arc<RwLock<SigilRuntimeCore>>>,
    Json(req): Json<TrustCheckRequest>,
) -> Json<TrustCheckResponse> {
    let runtime = runtime.read().unwrap();
    let loa = LOA::from_str(&req.loa).unwrap_or(LOA::Guest);
    let event = AuditEvent::new(
        &req.who,
        &req.action,
        req.target.as_deref(),
        &req.session_id,
        &loa,
    );

    let (allowed, score, model_id, threshold) = match (
        runtime.validate_action(&event),
        runtime.evaluate_event(&event),
    ) {
        (Ok(allowed), eval) => (
            allowed,
            eval.score.into(),
            runtime.active_model_id.clone(),
            Some(runtime.threshold),
        ),
        _ => (true, 0.0, None, None),
    };

    Json(TrustCheckResponse {
        allowed,
        score,
        model_id,
        threshold,
    })
}

#[axum::debug_handler]
async fn trust_status(
    Extension(runtime): Extension<Arc<RwLock<SigilRuntimeCore>>>,
) -> Json<serde_json::Value> {
    let runtime = runtime.read().unwrap();
    Json(runtime.status())
}

async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn readyz(Extension(runtime): Extension<Arc<RwLock<SigilRuntimeCore>>>) -> Json<serde_json::Value> {
    let runtime = runtime.read().unwrap();
    let ready = runtime.active_model_id.is_some();
    Json(serde_json::json!({ "ready": ready }))
}
