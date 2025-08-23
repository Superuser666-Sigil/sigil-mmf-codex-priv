use crate::audit::AuditEvent;
use crate::loa::LOA;
use crate::sigil_runtime_core::SigilRuntimeCore;
use axum::{
    extract::Extension,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use log::error;
use prometheus::{Encoder, IntCounter, Registry, TextEncoder};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::OnceLock;
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
    Router::new()
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
        .route("/metrics", get(metrics))
        .layer(Extension(runtime))
}

#[axum::debug_handler]
async fn check_trust(
    Extension(runtime): Extension<Arc<RwLock<SigilRuntimeCore>>>,
    Json(req): Json<TrustCheckRequest>,
) -> Result<Json<TrustCheckResponse>, (StatusCode, String)> {
    // increment metric
    init_metrics();
    if let Some(counter) = TRUST_CHECK_TOTAL.get() {
        counter.inc();
    }
    let runtime = runtime.read().map_err(|e| {
        error!("Runtime read lock poisoned: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "runtime lock poisoned".to_string(),
        )
    })?;
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

    Ok(Json(TrustCheckResponse {
        allowed,
        score,
        model_id,
        threshold,
    }))
}

#[axum::debug_handler]
async fn trust_status(
    Extension(runtime): Extension<Arc<RwLock<SigilRuntimeCore>>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let runtime = runtime.read().map_err(|e| {
        error!("Runtime read lock poisoned: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "runtime lock poisoned".to_string(),
        )
    })?;
    Ok(Json(runtime.status()))
}

async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn readyz(
    Extension(runtime): Extension<Arc<RwLock<SigilRuntimeCore>>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let runtime = runtime.read().map_err(|e| {
        error!("Runtime read lock poisoned: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "runtime lock poisoned".to_string(),
        )
    })?;
    let ready = runtime.active_model_id.is_some();
    Ok(Json(serde_json::json!({ "ready": ready })))
}

// Simple Prometheus metrics endpoint using a global registry
static METRICS_REGISTRY: OnceLock<Registry> = OnceLock::new();
static TRUST_CHECK_TOTAL: OnceLock<IntCounter> = OnceLock::new();

fn init_metrics() {
    let registry = METRICS_REGISTRY.get_or_init(Registry::new);
    let counter = TRUST_CHECK_TOTAL.get_or_init(|| {
        IntCounter::new("trust_check_total", "Total trust check requests").expect("counter")
    });
    let _ = registry.register(Box::new(counter.clone()));
}

async fn metrics() -> (axum::http::StatusCode, String) {
    init_metrics();
    let encoder = TextEncoder::new();
    let metric_families = METRICS_REGISTRY.get().unwrap().gather();
    let mut buffer = Vec::new();
    if encoder.encode(&metric_families, &mut buffer).is_err() {
        return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, String::new());
    }
    let body = String::from_utf8(buffer).unwrap_or_default();
    (axum::http::StatusCode::OK, body)
}
