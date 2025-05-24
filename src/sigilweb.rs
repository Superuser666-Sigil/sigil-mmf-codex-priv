use axum::{
    extract::{Extension, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use chrono::Utc;
use std::env;
use std::io;

use crate::sigil_runtime_core::SigilRuntimeCore;
use crate::audit::{AuditEvent, LogLevel};
use crate::loa::LOA;

#[derive(Debug, Deserialize)]
pub struct TrustCheckRequest {
    pub who: String,
    pub action: String,
    pub target: Option<String>,
    pub session_id: String,
    pub loa: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustCheckResponse {
    pub allowed: bool,
    pub score: f64,
    pub model_id: Option<String>,
    pub threshold: Option<f64>,
    pub timestamp: String,
    pub trace_id: Option<String>,
}

/// Canon-standard success wrapper
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SigilResponse<T> {
    pub success: bool,
    pub result: T,
    pub issued_at: String,
}

/// Build core trust routes into Axum router
pub fn build_trust_router(core: Arc<RwLock<SigilRuntimeCore>>) -> Router {
    Router::new()
        .route("/trust/check", post(trust_check))
        .route("/trust/status", get(service_status))
        .layer(Extension(core))
}

/// POST /trust/check
async fn trust_check(
    Json(req): Json<TrustCheckRequest>,
    Extension(core): Extension<Arc<RwLock<SigilRuntimeCore>>>,
) -> Json<SigilResponse<TrustCheckResponse>> {
    let parsed_loa = match LOA::from_str(&req.loa) {
        Ok(loa) => loa,
        Err(_) => {
            return Json(SigilResponse {
                success: false,
                result: TrustCheckResponse {
                    allowed: false,
                    score: 0.0,
                    model_id: None,
                    threshold: None,
                    timestamp: Utc::now().to_rfc3339(),
                    trace_id: None,
                },
                issued_at: Utc::now().to_rfc3339(),
            });
        }
    };

    let result = core.read().map_err(|e| {
        eprintln!("Failed to acquire runtime lock: {}", e);
        io::Error::new(io::ErrorKind::Other, "Runtime unavailable")
    }).and_then(|locked| {
        locked.evaluate(&req.who, &req.action, req.target.as_deref(), &parsed_loa)
            .map_err(|e| {
                eprintln!("Evaluation error: {}", e);
                io::Error::new(io::ErrorKind::Other, "Trust evaluation failed")
            })
    });

    match result {
        Ok(verdict) => {
            AuditEvent::trust_eval_success(&req.who, &req.action, &parsed_loa, &verdict);

            Json(SigilResponse {
                success: true,
                result: TrustCheckResponse {
                    allowed: verdict.allowed,
                    score: verdict.score,
                    model_id: verdict.model_id,
                    threshold: verdict.threshold,
                    timestamp: Utc::now().to_rfc3339(),
                    trace_id: verdict.trace_id,
                },
                issued_at: Utc::now().to_rfc3339(),
            })
        }
        Err(_) => Json(SigilResponse {
            success: false,
            result: TrustCheckResponse {
                allowed: false,
                score: 0.0,
                model_id: None,
                threshold: None,
                timestamp: Utc::now().to_rfc3339(),
                trace_id: None,
            },
            issued_at: Utc::now().to_rfc3339(),
        }),
    }
}

/// GET /trust/status
async fn service_status() -> Json<SigilResponse<String>> {
    Json(SigilResponse {
        success: true,
        result: "sigil-web status ok".to_string(),
        issued_at: Utc::now().to_rfc3339(),
    })
}

/// Safe port parsing from environment
pub fn get_server_port() -> Result<u16, io::Error> {
    let port_str = env::var("PORT")
        .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "PORT env not set"))?;
    let port = port_str
        .parse::<u16>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "PORT not a u16"))?;
    Ok(port)
}
