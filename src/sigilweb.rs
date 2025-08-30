use crate::audit::AuditEvent;
use crate::loa::LOA;
use crate::sigil_runtime_core::SigilRuntimeCore;
use crate::input_validator::InputValidator;
use crate::rate_limiter::RateLimiter;
use crate::csrf_protection::CSRFProtection;
use crate::module_loader::ModuleContext;
use axum::{
    Router,
    extract::Extension,
    http::{StatusCode, HeaderMap},
    response::Json,
    routing::{get, post},
};
use log::{error, info};
use prometheus::{Encoder, IntCounter, Registry, TextEncoder};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::OnceLock;
use std::sync::{Arc, RwLock};
use sha2::{Digest};
use hex;

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

#[derive(Debug, Deserialize, Serialize)]
pub struct ModuleRunRequest {
    pub input: String,
    pub session_id: String,
    pub user_id: String,
}

#[derive(Debug, Serialize)]
pub struct ModuleRunResponse {
    output: String,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CanonWriteRequest {
    key: String,
    value: String,
    session_id: String,
}

#[derive(Debug, Serialize)]
pub struct CanonWriteResponse {
    success: bool,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SystemProposalRequest {
    entry: String,
    content: String,
    required_k: usize,
}

#[derive(Debug, Serialize)]
pub struct SystemProposalResponse {
    proposal_id: String,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SystemAttestRequest {
    proposal_id: String,
    witness_id: String,
    signature: String,
}

#[derive(Debug, Serialize)]
pub struct SystemAttestResponse {
    success: bool,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CSRFTokenRequest {
    session_id: String,
}

#[derive(Debug, Serialize)]
pub struct CSRFTokenResponse {
    token: String,
    expires_in: u64,
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
        .route("/api/audit/{id}", get(get_audit))
        .route("/api/module/{name}/run", post(run_module))
        .route("/api/canon/user/write", post(canon_user_write))
        .route("/api/canon/system/propose", post(canon_system_propose))
        .route("/api/canon/system/attest", post(canon_system_attest))
        .route("/api/csrf/token", post(mint_csrf_token))
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
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Rate limit check failed: {e}")))? {
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
        return Err((StatusCode::BAD_REQUEST, format!("Input validation failed: {e}")));
    }
    
    // increment metric
    init_metrics();
    if let Some(counter) = TRUST_CHECK_TOTAL.get() {
        counter.inc();
    }
    let loa = LOA::from_str(&req.loa).unwrap_or(LOA::Guest);
    let event = AuditEvent::new(
        &req.who,
        &req.action,
        req.target.as_deref(),
        &req.session_id,
        &loa,
    );

    // Compute the number of recent requests for rate limiting.  This
    // value is passed into the trust evaluation to inform the model
    // about client activity.  The rate limiter call cannot fail, so
    // we use the returned count directly.
    let recent_requests = rate_limiter.get_request_count(client_id).await;

    // Evaluate trust using the logistic model via the runtime.  This
    // call always succeeds; logistic evaluation uses the configured
    // model registry.  Score is a f64 and allowed is a boolean.
    let (eval, allowed, actual_threshold) = {
        let runtime = runtime.read().map_err(|e| {
            error!("Runtime read lock poisoned: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "runtime lock poisoned".to_string(),
            )
        })?;
        let eval = runtime.evaluate_event(&event, recent_requests);
        let allowed = match runtime.validate_action(&event, recent_requests) {
            Ok(a) => a,
            Err(e) => {
                error!("Trust validation failed for {}: {}", req.action, e);
                false
            }
        };
        (eval, allowed, runtime.threshold)
    };
    // Use default threshold for logistic model; model_id is None for logistic
    let score = eval.score as f64;
    let model_id = None;
    let threshold = Some(actual_threshold); // Use actual runtime threshold
    let error_msg = None;
    Ok(Json(TrustCheckResponse {
        allowed,
        score,
        model_id,
        threshold,
        error: error_msg,
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
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Rate limit check failed: {e}")))? {
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
        return Err((StatusCode::BAD_REQUEST, format!("Input validation failed: {e}")));
    }
    
    let _loa = match LOA::from_str(&req.loa) {
        Ok(loa) => loa,
        Err(_) => {
            return Err((StatusCode::BAD_REQUEST, format!("Invalid LOA: {}", req.loa)));
        }
    };
    // Optionally use runtime if needed (for consistency)
    let _runtime = runtime.read().map_err(|e| {
        error!("Runtime read lock poisoned: {e}");
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
        error!("Runtime read lock poisoned: {e}");
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

async fn readyz() -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // In logistic-only MVP, always ready since builtin model is always available
    Ok(Json(serde_json::json!({ "ready": true })))
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

// New API endpoint handlers

#[axum::debug_handler]
async fn get_audit(
    Extension(runtime): Extension<Arc<RwLock<SigilRuntimeCore>>>,
    axum::extract::Path(audit_id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // SECURITY: Verify signature before returning audit data
    // This is a placeholder - in a real implementation, you'd load the audit from storage
    // and verify its signature using the ReasoningChain::verify_integrity() method
    
    let _runtime = runtime.read().map_err(|e| {
        error!("Runtime read lock poisoned: {e}");
        (StatusCode::INTERNAL_SERVER_ERROR, "runtime lock poisoned".to_string())
    })?;
    
    // For now, return a mock response
    Ok(Json(serde_json::json!({
        "audit_id": audit_id,
        "verified": true,
        "content": "audit content would be here"
    })))
}

#[axum::debug_handler]
async fn run_module(
    Extension(runtime): Extension<Arc<RwLock<SigilRuntimeCore>>>,
    Extension(rate_limiter): Extension<Arc<RateLimiter>>,
    Extension(csrf_protection): Extension<Arc<CSRFProtection>>,
    axum::extract::Path(module_name): axum::extract::Path<String>,
    headers: HeaderMap,
    Json(req): Json<ModuleRunRequest>,
) -> Result<Json<ModuleRunResponse>, (StatusCode, String)> {
    // Rate limiting
    let client_id = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");
    
    if !rate_limiter.check_rate_limit(client_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Rate limit check failed: {e}")))? {
        return Err((StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded".to_string()));
    }
    
    // CSRF protection
    if let Some(csrf_token) = headers.get("x-csrf-token") {
        if let Ok(token) = csrf_token.to_str() {
            if !csrf_protection.validate_token(&req.session_id, token).await {
                return Err((StatusCode::FORBIDDEN, "Invalid CSRF token".to_string()));
            }
        }
    }
    
    // Validate user_id is not empty
    if req.user_id.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "user_id cannot be empty".to_string()));
    }
    
    // Get recent requests count first
    let recent_requests = rate_limiter.get_request_count(client_id).await;
    
    // Create audit event and evaluate trust, then execute module
    let module_result = {
        let runtime = runtime.read().map_err(|e| {
            error!("Runtime read lock poisoned: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "runtime lock poisoned".to_string())
        })?;
        
        let event = AuditEvent::new(
            &req.user_id,
            "module_execute",
            Some(&module_name),
            &req.session_id,
            &runtime.loa,
        );
        
        let evaluation = runtime.evaluate_event(&event, recent_requests);
        
        if !evaluation.allowed {
            return Err((StatusCode::FORBIDDEN, "Module execution denied by trust evaluation".to_string()));
        }
        
        // Create module execution context
        let module_context = ModuleContext {
            session_id: req.session_id.clone(),
            user_id: req.user_id.clone(),
            loa: runtime.loa.clone(),
            input: req.input.clone(),
        };
        
        // Execute the module through the registry
        let module_registry = runtime.module_registry.lock().map_err(|e| {
            error!("Module registry lock poisoned: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "module registry lock poisoned".to_string())
        })?;
        
        module_registry.run_module(&module_name, &module_context)
            .map_err(|e| match e {
                crate::errors::SigilError::Internal { message } if message.contains("not found") => 
                    (StatusCode::NOT_FOUND, format!("Module '{}' not found", module_name)),
                crate::errors::SigilError::InsufficientLoa { .. } => 
                    (StatusCode::FORBIDDEN, format!("Insufficient LOA for module '{}'", module_name)),
                _ => (StatusCode::INTERNAL_SERVER_ERROR, format!("Module execution failed: {}", e))
            })?
    };
    
    info!("Successfully executed module '{}' for user '{}'", module_name, req.user_id);
    
    Ok(Json(ModuleRunResponse {
        output: module_result,
        error: None,
    }))
}

#[axum::debug_handler]
async fn canon_user_write(
    Extension(runtime): Extension<Arc<RwLock<SigilRuntimeCore>>>,
    Extension(rate_limiter): Extension<Arc<RateLimiter>>,
    Extension(csrf_protection): Extension<Arc<CSRFProtection>>,
    headers: HeaderMap,
    Json(req): Json<CanonWriteRequest>,
) -> Result<Json<CanonWriteResponse>, (StatusCode, String)> {
    // Rate limiting and CSRF protection
    let client_id = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");
    
    if !rate_limiter.check_rate_limit(client_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Rate limit check failed: {e}")))? {
        return Err((StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded".to_string()));
    }
    
    if let Some(csrf_token) = headers.get("x-csrf-token") {
        if let Ok(token) = csrf_token.to_str() {
            if !csrf_protection.validate_token(&req.session_id, token).await {
                return Err((StatusCode::FORBIDDEN, "Invalid CSRF token".to_string()));
            }
        }
    }
    
    // Validate key and value are not empty
    if req.key.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "key cannot be empty".to_string()));
    }
    if req.value.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "value cannot be empty".to_string()));
    }
    
    // Create audit event for canon write
    let event = AuditEvent::new(
        "user",
        "canon_write",
        Some(&req.key),
        &req.session_id,
        &LOA::Observer, // Default LOA for user writes
    );
    
    // Evaluate trust for canon write
    let recent_requests = rate_limiter.get_request_count(client_id).await;
    let evaluation = {
        let runtime = runtime.read().map_err(|e| {
            error!("Runtime read lock poisoned: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "runtime lock poisoned".to_string())
        })?;
        runtime.evaluate_event(&event, recent_requests)
    };
    
    if !evaluation.allowed {
        return Err((StatusCode::FORBIDDEN, "Canon write denied by trust evaluation".to_string()));
    }
    
    // Now implement real canon write with signing
    let write_result = {
        let runtime = runtime.read().map_err(|e| {
            error!("Runtime read lock poisoned: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "runtime lock poisoned".to_string())
        })?;
        
        // Create a CanonicalRecord from the key/value
        let payload = serde_json::json!({
            "key": req.key,
            "value": req.value,
            "session_id": req.session_id
        });
        
        let mut record = crate::canonical_record::CanonicalRecord {
            kind: "user_data".to_string(),
            schema_version: 1,
            id: req.key.clone(),
            tenant: "user".to_string(),
            ts: chrono::Utc::now(),
            space: "user".to_string(),
            payload,
            links: vec![],
            prev: None,
            hash: String::new(), // Will be computed
            sig: None,           // Will be signed
            pub_key: None,       // Will be set from key store
            witnesses: vec![],
        };
        
        // Canonicalize → hash → sign → persist CanonicalRecord
        let canonical_json = record.to_canonical_json()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Canonicalization failed: {e}")))?;
        
        // Compute hash
        let mut hasher = sha2::Sha256::new();
        hasher.update(canonical_json.as_bytes());
        let digest = hasher.finalize();
        record.hash = hex::encode(digest);
        
        // Sign with active key from KeyStore
        let signing_key = crate::keys::KeyManager::get_or_create_canon_key()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get signing key: {e}")))?;
        
        let (signature, public_key) = signing_key.sign_record(canonical_json.as_bytes());
        
        record.sig = Some(signature);
        record.pub_key = Some(public_key);
        
        // Persist to Canon Store
        let mut canon_store = runtime.canon_store.lock().map_err(|e| {
            error!("Canon store lock poisoned: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "canon store lock poisoned".to_string())
        })?;
        
        canon_store.add_record(record, &LOA::Observer, false)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to persist record: {e}")))?;
        
        Ok::<(), (StatusCode, String)>(())
    };
    
    match write_result {
        Ok(()) => {
            info!("Successfully wrote canon record for key: {}", req.key);
            Ok(Json(CanonWriteResponse {
                success: true,
                error: None,
            }))
        },
        Err(e) => Err(e)
    }
}

#[axum::debug_handler]
async fn canon_system_propose(
    Extension(runtime): Extension<Arc<RwLock<SigilRuntimeCore>>>,
    Extension(rate_limiter): Extension<Arc<RateLimiter>>,
    Extension(csrf_protection): Extension<Arc<CSRFProtection>>,
    headers: HeaderMap,
    Json(req): Json<SystemProposalRequest>,
) -> Result<Json<SystemProposalResponse>, (StatusCode, String)> {
    // Rate limiting and CSRF protection
    let client_id = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");
    
    if !rate_limiter.check_rate_limit(client_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Rate limit check failed: {e}")))? {
        return Err((StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded".to_string()));
    }
    
    if let Some(csrf_token) = headers.get("x-csrf-token") {
        if let Ok(token) = csrf_token.to_str() {
            if !csrf_protection.validate_token("system_propose", token).await {
                return Err((StatusCode::FORBIDDEN, "Invalid CSRF token".to_string()));
            }
        }
    }
    
    // Validate required fields
    if req.entry.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "entry cannot be empty".to_string()));
    }
    if req.content.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "content cannot be empty".to_string()));
    }
    if req.required_k == 0 {
        return Err((StatusCode::BAD_REQUEST, "required_k must be greater than 0".to_string()));
    }
    
    // Create audit event for system proposal
    let event = AuditEvent::new(
        "system",
        "propose",
        Some(&req.entry),
        "system_propose",
        &LOA::Operator, // System proposals require Operator LOA
    );
    
    // Evaluate trust for system proposal
    let recent_requests = rate_limiter.get_request_count(client_id).await;
    let evaluation = {
        let runtime = runtime.read().map_err(|e| {
            error!("Runtime read lock poisoned: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "runtime lock poisoned".to_string())
        })?;
        runtime.evaluate_event(&event, recent_requests)
    };
    
    if !evaluation.allowed {
        return Err((StatusCode::FORBIDDEN, "System proposal denied by trust evaluation".to_string()));
    }
    
    // Create proposal in the quorum system
    let proposal_id = {
        let runtime = runtime.read().map_err(|e| {
            error!("Runtime read lock poisoned: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "runtime lock poisoned".to_string())
        })?;
        
        let mut quorum_system = runtime.quorum_system.lock().map_err(|e| {
            error!("Quorum system lock poisoned: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "quorum system lock poisoned".to_string())
        })?;
        
        quorum_system.create_proposal(req.entry, req.content, req.required_k)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create proposal: {e}")))?
    };
    
    info!("Created system proposal {} requiring {}-of-n signatures", proposal_id, req.required_k);
    
    Ok(Json(SystemProposalResponse {
        proposal_id,
        error: None,
    }))
}

#[axum::debug_handler]
async fn canon_system_attest(
    Extension(runtime): Extension<Arc<RwLock<SigilRuntimeCore>>>,
    Extension(rate_limiter): Extension<Arc<RateLimiter>>,
    Extension(csrf_protection): Extension<Arc<CSRFProtection>>,
    headers: HeaderMap,
    Json(req): Json<SystemAttestRequest>,
) -> Result<Json<SystemAttestResponse>, (StatusCode, String)> {
    // Rate limiting and CSRF protection
    let client_id = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");
    
    if !rate_limiter.check_rate_limit(client_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Rate limit check failed: {e}")))? {
        return Err((StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded".to_string()));
    }
    
    if let Some(csrf_token) = headers.get("x-csrf-token") {
        if let Ok(token) = csrf_token.to_str() {
            if !csrf_protection.validate_token(&req.witness_id, token).await {
                return Err((StatusCode::FORBIDDEN, "Invalid CSRF token".to_string()));
            }
        }
    }
    
    // Validate required fields
    if req.proposal_id.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "proposal_id cannot be empty".to_string()));
    }
    if req.signature.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "signature cannot be empty".to_string()));
    }
    if req.witness_id.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "witness_id cannot be empty".to_string()));
    }
    
    // Create audit event for system attestation
    let event = AuditEvent::new(
        &req.witness_id,
        "attest",
        Some(&req.proposal_id),
        "system_attest",
        &LOA::Operator, // System attestations require Operator LOA
    );
    
    // Evaluate trust for system attestation
    let recent_requests = rate_limiter.get_request_count(client_id).await;
    let evaluation = {
        let runtime = runtime.read().map_err(|e| {
            error!("Runtime read lock poisoned: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "runtime lock poisoned".to_string())
        })?;
        runtime.evaluate_event(&event, recent_requests)
    };
    
    if !evaluation.allowed {
        return Err((StatusCode::FORBIDDEN, "System attestation denied by trust evaluation".to_string()));
    }
    
    // Add signature to the proposal and check if quorum is reached
    let proposal_result = {
        let runtime = runtime.read().map_err(|e| {
            error!("Runtime read lock poisoned: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "runtime lock poisoned".to_string())
        })?;
        
        let mut quorum_system = runtime.quorum_system.lock().map_err(|e| {
            error!("Quorum system lock poisoned: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "quorum system lock poisoned".to_string())
        })?;
        
        // Add the signature to the proposal
        quorum_system.add_signature(&req.proposal_id, req.witness_id.clone(), req.signature)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Failed to add signature: {e}")))?;
        
        // Check if the proposal now has quorum and can be committed
        quorum_system.get_proposal(&req.proposal_id)
            .map(|p| (p.has_quorum(), p.get_signature_count(), p.required_k))
            .ok_or_else(|| (StatusCode::NOT_FOUND, "Proposal not found".to_string()))?
    };
    
    let (has_quorum, current_sigs, required_k) = proposal_result;
    
    if has_quorum {
        // TODO: Here we should commit the proposal to Canon
        // For now, just log that quorum was reached
        info!("Proposal {} reached quorum with {}/{} signatures", req.proposal_id, current_sigs, required_k);
    } else {
        info!("Proposal {} has {}/{} signatures (quorum not yet reached)", req.proposal_id, current_sigs, required_k);
    }
    
    Ok(Json(SystemAttestResponse {
        success: true,
        error: None,
    }))
}

#[axum::debug_handler]
async fn mint_csrf_token(
    Extension(rate_limiter): Extension<Arc<RateLimiter>>,
    Extension(csrf_protection): Extension<Arc<CSRFProtection>>,
    headers: HeaderMap,
    Json(req): Json<CSRFTokenRequest>,
) -> Result<Json<CSRFTokenResponse>, (StatusCode, String)> {
    // Rate limiting
    let client_id = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");
    
    if !rate_limiter.check_rate_limit(client_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Rate limit check failed: {e}")))? {
        return Err((StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded".to_string()));
    }
    
    // Validate session_id is not empty
    if req.session_id.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "session_id cannot be empty".to_string()));
    }
    
    // Mint a new CSRF token
    let token = csrf_protection.generate_token(&req.session_id).await;
    
    // Log the token minting for security audit
    log::info!("CSRF token minted for session: {} from client: {}", req.session_id, client_id);
    
    Ok(Json(CSRFTokenResponse {
        token,
        expires_in: 3600, // 1 hour
        error: None,
    }))
}
