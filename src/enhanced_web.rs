use axum::{Router, routing::{get, post}, extract::State};
use std::sync::Arc;

use crate::{
    app_state::AppState,
    api::{
        license::create_license_root_only,
        quorum::commit_system_proposal,
        memory::{memory_write, memory_list, rag_upsert},
    },
    // sigilweb::build_trust_router, // unused here; kept exported elsewhere
};

/// Build a comprehensive router with all API endpoints
pub fn build_enhanced_router(app_state: Arc<AppState>) -> Router<Arc<AppState>> {
    // Create a new router with the app state
    Router::new()
        // License management (Root only)
        .route("/api/license/create", post(create_license_root_only))
        
        // Quorum system
        .route("/api/canon/system/commit", post(commit_system_proposal))
        
        // Memory and RAG endpoints
        .route("/api/memory/write", post(memory_write))
        .route("/api/memory/list", get(memory_list))
        .route("/api/rag/upsert", post(rag_upsert))
        
        // Module endpoints (enhanced)
        .route("/api/module/rust_mentor/run", post(run_rust_mentor_module))
        
        // License validation endpoint
        .route("/api/license/validate", post(validate_license_endpoint))
        
        // Bootstrap endpoint (for initial Root license creation)
        .route("/api/license/bootstrap", post(bootstrap_root_license))
        
        .with_state(app_state)
}

// Enhanced module runner for Rust mentor
async fn run_rust_mentor_module(
    State(st): State<Arc<AppState>>,
    axum::Json(req): axum::Json<crate::sigilweb::ModuleRunRequest>,
) -> Result<axum::Json<crate::sigilweb::ModuleRunResponse>, crate::api_errors::AppError> {
    use crate::module::SigilModule;
    
    // Get runtime core
    let runtime = st.runtime_core.read().await;
    
    // Create Rust mentor module
    let module = crate::module::RustMentorModule::new();
    
    // Run the module
    match module.run(req.input, &req.session_id, &req.user_id, &*runtime).await {
        Ok(output) => Ok(axum::Json(crate::sigilweb::ModuleRunResponse::from_output(output))),
        Err(e) => Ok(axum::Json(crate::sigilweb::ModuleRunResponse::from_error(e.to_string()))),
    }
}

// License validation endpoint
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct ValidateLicenseRequest {
    license_content: String,
}

#[derive(Serialize)]
struct ValidateLicenseResponse {
    valid: bool,
    loa: Option<String>,
    owner_id: Option<String>,
    error: Option<String>,
}

async fn validate_license_endpoint(
    State(_st): State<Arc<AppState>>,
    axum::Json(_req): axum::Json<ValidateLicenseRequest>,
) -> Result<axum::Json<ValidateLicenseResponse>, crate::api_errors::AppError> {
    // TODO: Implement license validation logic
    // For now, return a mock response
    Ok(axum::Json(ValidateLicenseResponse {
        valid: true,
        loa: Some("operator".to_string()),
        owner_id: Some("test_user".to_string()),
        error: None,
    }))
}

// Bootstrap endpoint for initial Root license creation
#[derive(Deserialize)]
struct BootstrapRequest {
    owner_id: String,
    owner_name: String,
    expires_at: String,
    passphrase: String,
}

#[derive(Serialize)]
struct BootstrapResponse {
    success: bool,
    license_toml: Option<String>,
    error: Option<String>,
}

async fn bootstrap_root_license(
    State(st): State<Arc<AppState>>,
    axum::Json(req): axum::Json<BootstrapRequest>,
) -> Result<axum::Json<BootstrapResponse>, crate::api_errors::AppError> {
    // Check if bootstrap is enabled
    let bootstrap_enabled = std::env::var("MMF_BOOTSTRAP")
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(false);
        
    if !bootstrap_enabled {
        return Err(crate::api_errors::AppError::forbidden("Bootstrap not enabled"));
    }
    
    // TODO: Check if Root license already exists
    
    // Create Root license using the CLI logic
    use crate::crypto::KeyStore;
    use ed25519_dalek::Signer;
    use sha2::{Sha256, Digest};
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as b64;
    use time::{OffsetDateTime, format_description::well_known::Rfc3339};
    
    let ks = KeyStore::new(&st.key_dir);
    let (sk, pk_b64) = ks.load_or_create_ed25519("root_license.ed25519.enc", &req.passphrase)
        .map_err(|_| crate::api_errors::AppError::internal("Failed to create root key"))?;
    
    // Use the same license structure as the CLI
    #[derive(Serialize)]
    struct License<'a> {
        owner: Owner<'a>,
        loa: &'a str,
        #[serde(rename = "issuedAt")]
        issued_at: String,
        #[serde(rename = "expiresAt")]
        expires_at: &'a str,
        bindings: Bindings<'a>,
    }
    
    #[derive(Serialize)]
    struct Owner<'a> { id: &'a str, name: &'a str }
    
    #[derive(Serialize)]
    struct Bindings<'a> { 
        #[serde(rename = "runtimeId")]
        runtime_id: &'a str, 
        #[serde(rename = "canonFingerprint")]
        canon_fingerprint: &'a str 
    }
    
    #[derive(Serialize)]
    struct Sealed<'a> { license: License<'a>, seal: Seal<'a> }
    
    #[derive(Serialize)]
    struct Seal<'a> {
        alg: &'a str,
        sig: String,
        pubkey: String,
        #[serde(rename = "contentHash")]
        content_hash: String,
    }
    
    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    let lic = License {
        owner: Owner { id: &req.owner_id, name: &req.owner_name },
        loa: "root",
        issued_at: now,
        expires_at: &req.expires_at,
        bindings: Bindings { 
            runtime_id: &st.runtime_id, 
            canon_fingerprint: &st.canon_fingerprint 
        },
    };
    
    // Canonicalize and sign (same as CLI)
    fn canonical_json_bytes<T: Serialize>(v: &T) -> Vec<u8> {
        let val = serde_json::to_value(v).expect("ser");
        fn sort(v: &serde_json::Value) -> serde_json::Value {
            match v {
                serde_json::Value::Object(m) => {
                    let mut b = std::collections::BTreeMap::new();
                    for (k, vv) in m { b.insert(k.clone(), sort(vv)); }
                    serde_json::Value::Object(b.into_iter().collect())
                }
                serde_json::Value::Array(a) => serde_json::Value::Array(a.iter().map(sort).collect()),
                _ => v.clone()
            }
        }
        serde_json::to_vec(&sort(&val)).unwrap()
    }
    
    let cbytes = canonical_json_bytes(&lic);
    let hash = Sha256::digest(&cbytes);
    let sig = sk.sign(&cbytes);
    
    let sealed = Sealed {
        license: lic,
        seal: Seal {
            alg: "ed25519",
            sig: b64.encode(sig.to_bytes()),
            pubkey: pk_b64,
            content_hash: b64.encode(hash),
        }
    };
    
    let toml_str = toml::to_string_pretty(&sealed)
        .map_err(|_| crate::api_errors::AppError::internal("TOML serialization failed"))?;
    
    Ok(axum::Json(BootstrapResponse {
        success: true,
        license_toml: Some(toml_str),
        error: None,
    }))
}
