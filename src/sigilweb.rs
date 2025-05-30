use crate::audit_store::write_chain;
use crate::trust_registry::{register_scope, release_scope};
use axum::Router;
use crate::session_context::SessionContext;

pub fn build_routes<S>() -> Router
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
}


use axum::{
    extract::{Extension, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::sigil_runtime_core::SigilRuntimeCore;
use crate::audit::AuditEvent;
use crate::loa::LOA;

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

async fn check_trust(
    Extension(runtime): Extension<Arc<RwLock<SigilRuntimeCore>>>,
    Json(req): Json<TrustCheckRequest>,
) -> Json<TrustCheckResponse> {
    let runtime = runtime.read().unwrap();
    let loa = LOA::from_str(&req.loa).unwrap_or(LOA::Guest);
    let event = AuditEvent::new(&req.who, &req.action, req.target.as_deref(), &req.session_id, &loa);

    let (allowed, score, model_id, threshold) = match (
        runtime.validate_action(&event),
        runtime.evaluate_event(&event),
    ) {
        (Ok(allowed), eval) => (
            allowed,
            eval.score,
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

async fn trust_status(
    Extension(runtime): Extension<Arc<RwLock<SigilRuntimeCore>>>,
) -> Json<serde_json::Value> {
    let runtime = runtime.read().unwrap();
    Json(runtime.status())
}