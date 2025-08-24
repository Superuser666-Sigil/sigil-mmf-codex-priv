use crate::audit::AuditEvent;
use crate::loa::LOA;
use crate::sigil_runtime_core::SigilRuntimeCore;
use crate::input_validator::InputValidator;
use crate::rate_limiter::RateLimiter;
use crate::csrf_protection::CSRFProtection;
use axum::{
    Router,
    extract::Extension,
    http::{StatusCode, HeaderMap},
    response::Json,
    routing::{get, post},
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
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ExtensionRegisterRequest {
    name: String,
    loa: String,
}

#[derive(Debug, Serialize)]
pub struct ExtensionRegisterResponse {
    registered: bool,
    error: Option<String>,
}

// Add trust-related routes
pub fn add_trust_routes(router: Router, runtime: Arc<RwLock<SigilRuntimeCore>>) -> Router {
    // Initialize security components
    let rate_limiter = Arc::new(RateLimiter::new(100, 60)); // 100 requests per minute
    let csrf_protection = Arc::new(CSRFProtection::new(3600)); // 1 hour token lifetime
    
    router
        .route("/api/trust/check", post(check_trust))
        .route("/api/trust/status", get(trust_status))
        .route("/api/extensions/register", post(register_extension_api))
        .layer(Extension(runtime))
        .layer(Extension(rate_limiter))
        .layer(Extension(csrf_protection))
}

/// Build a minimal router exposing trust endpoints, versioned alias, and health checks
pub fn build_trust_router(runtime: Arc<RwLock<SigilRuntimeCore>>) -> Router {
    // Initialize security components
    let rate_limiter = Arc::new(RateLimiter::new(100, 60)); // 100 requests per minute
    let csrf_protection = Arc::new(CSRFProtection::new(3600)); // 1 hour token lifetime
    
    Router::new()
        // current endpoints
        .route("/api/trust/check", post(check_trust))
        .route("/api/trust/status", get(trust_status))
        .route("/api/extensions/register", post(register_extension_api))
        // versioned aliases
        .route("/v1/trust/check", post(check_trust))
        .route("/v1/trust/status", get(trust_status))
        .route("/v1/extensions/register", post(register_extension_api))
        // backward-compatible aliases used by some tests
        .route("/trust/check", post(check_trust))
        .route("/trust/status", get(trust_status))
        // health endpoints
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .layer(Extension(runtime))
        .layer(Extension(rate_limiter))
        .layer(Extension(csrf_protection))
}

#[axum::debug_handler]
async fn check_trust(
    Extension(runtime): Extension<Arc<RwLock<SigilRuntimeCore>>>,
    Extension(rate_limiter): Extension<Arc<RateLimiter>>,
    Extension(csrf_protection): Extension<Arc<CSRFProtection>>,
    headers: HeaderMap,
    Json(req): Json<TrustCheckRequest>,
) -> Result<Json<TrustCheckResponse>, (StatusCode, String)> {
    // Rate limiting check
    let client_id = headers.get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");
    
    if !rate_limiter.check_rate_limit(client_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Rate limit check failed: {}", e)))? {
        return Err((StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded".to_string()));
    }
    
    // CSRF protection check
    if let Some(csrf_token) = headers.get("x-csrf-token") {
        if let Ok(token) = csrf_token.to_str() {
            if !csrf_protection.validate_token(&req.session_id, token).await {
                return Err((StatusCode::FORBIDDEN, "Invalid CSRF token".to_string()));
            }
        }
    }
    
    // Validate input
    let validator = InputValidator::new();
    if let Err(e) = validator.validate_trust_request(&crate::input_validator::TrustCheckRequest {
        who: req.who.clone(),
        action: req.action.clone(),
        target: req.target.clone(),
        session_id: req.session_id.clone(),
        loa: req.loa.clone(),
    }) {
        return Err((StatusCode::BAD_REQUEST, format!("Input validation failed: {}", e)));
    }
    
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

    let eval_result = if let Some(model_id) = &runtime.active_model_id {
        runtime
            .trust_evaluator
            .evaluate_event(&event, model_id)
            .map(|(s, a)| (s as f64, a))
    } else {
        Err("No active model available".to_string())
    };

    let (allowed, score, model_id, threshold, error) =
        match (runtime.validate_action(&event), eval_result) {
            (Ok(allowed), Ok((score, _))) => (
                allowed,
                score,
                runtime.active_model_id.clone(),
                Some(runtime.threshold),
                None,
            ),
            (Err(e), _) => {
                error!("Trust validation failed for {}: {}", req.action, e);
                (false, 0.0, None, None, Some(e.to_string()))
            }
            (_, Err(e)) => {
                error!("Trust evaluation failed for {}: {}", req.action, e);
                (false, 0.0, None, None, Some(e))
            }
        };

    Ok(Json(TrustCheckResponse {
        allowed,
        score,
        model_id,
        threshold,
        error,
    }))
}

#[axum::debug_handler]
async fn register_extension_api(
    Extension(runtime): Extension<Arc<RwLock<SigilRuntimeCore>>>,
    Extension(rate_limiter): Extension<Arc<RateLimiter>>,
    Extension(csrf_protection): Extension<Arc<CSRFProtection>>,
    headers: HeaderMap,
    Json(req): Json<ExtensionRegisterRequest>,
) -> Result<Json<ExtensionRegisterResponse>, (StatusCode, String)> {
    // Rate limiting check
    let client_id = headers.get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");
    
    if !rate_limiter.check_rate_limit(client_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Rate limit check failed: {}", e)))? {
        return Err((StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded".to_string()));
    }
    
    // CSRF protection check
    if let Some(csrf_token) = headers.get("x-csrf-token") {
        if let Ok(token) = csrf_token.to_str() {
            // For extension registration, we'll use the name as session ID
            if !csrf_protection.validate_token(&req.name, token).await {
                return Err((StatusCode::FORBIDDEN, "Invalid CSRF token".to_string()));
            }
        }
    }
    
    // Input validation using the validator
    let validator = InputValidator::new();
    if let Err(e) = validator.validate_extension_registration(&crate::input_validator::ExtensionRegisterRequest {
        name: req.name.clone(),
        loa: req.loa.clone(),
    }) {
        return Err((StatusCode::BAD_REQUEST, format!("Input validation failed: {}", e)));
    }
    
    let _loa = match LOA::from_str(&req.loa) {
        Ok(loa) => loa,
        Err(_) => {
            return Err((StatusCode::BAD_REQUEST, format!("Invalid LOA: {}", req.loa)));
        }
    };
    // Optionally use runtime if needed (for consistency)
    let _runtime = runtime.read().map_err(|e| {
        error!("Runtime read lock poisoned: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "runtime lock poisoned".to_string(),
        )
    })?;
    match crate::extensions::register_extension(&req.name, &req.loa) {
        Ok(_) => Ok(Json(ExtensionRegisterResponse {
            registered: true,
            error: None,
        })),
        Err(e) => {
            error!("Extension registration failed for {}: {}", req.name, e);
            Err((StatusCode::BAD_REQUEST, e))
        }
    }
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
        IntCounter::new("trust_check_total", "Total trust check requests")
            .unwrap_or_else(|_| {
                error!("Failed to create trust check counter");
                IntCounter::new("trust_check_total_fallback", "Fallback counter").unwrap()
            })
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
