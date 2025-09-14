use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use sha2::{Sha256, Digest};
use ed25519_dalek::Signer;
use base64::Engine as _; 
use base64::engine::general_purpose::STANDARD as b64;
use std::{sync::Arc, path::PathBuf};

use crate::{
    api_errors::AppError,
    security::{CurrentUser, extract_current_user_from_headers},
    app_state::AppState,
    loa::LOA,
};

/// Canonicalize deterministically using the same method as the CLI
fn canonical_json_bytes<T: Serialize>(v: &T) -> Vec<u8> {
    let val = serde_json::to_value(v).expect("serialization should not fail");
    fn sort(v: &serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(m) => {
                let mut b = std::collections::BTreeMap::new();
                for (k, vv) in m { 
                    b.insert(k.clone(), sort(vv)); 
                }
                serde_json::Value::Object(b.into_iter().collect())
            }
            serde_json::Value::Array(a) => serde_json::Value::Array(a.iter().map(sort).collect()),
            _ => v.clone()
        }
    }
    serde_json::to_vec(&sort(&val)).unwrap()
}

#[derive(Deserialize)]
pub struct CreateLicenseRequest {
    owner_id: String,
    owner_name: String,
    loa: String,                // "mentor" | "operator" | "observer" | "guest" (NOT root)
    expires_at: String,         // RFC3339
}

#[derive(Serialize)]
pub struct CreateLicenseResponse {
    file_path: String,
    toml: String,
}

#[axum::debug_handler]
pub async fn create_license_root_only(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CreateLicenseRequest>,
) -> Result<(StatusCode, Json<CreateLicenseResponse>), AppError> {
    let user: CurrentUser = extract_current_user_from_headers(&headers)?;
    if user.loa != LOA::Root {
        return Err(AppError::forbidden("only root can create licenses"));
    }
    if req.loa.to_lowercase() == "root" {
        return Err(AppError::bad_request("cannot mint additional root licenses"));
    }

    // Validate the requested LOA
    let _requested_loa = match req.loa.to_lowercase().as_str() {
        "mentor" => LOA::Mentor,
        "operator" => LOA::Operator,
        "observer" => LOA::Observer,
        "guest" => LOA::Guest,
        _ => return Err(AppError::bad_request("invalid LOA level")),
    };

    // gather runtime bindings
    let runtime_id = st.runtime_id.clone();
    let canon_fp = st.canon_fingerprint.clone();

    // load signing key
    let pass = st.license_passphrase.clone()
        .ok_or_else(|| AppError::internal("missing license passphrase"))?;
    let (sk, pk_b64) = st.key_store.load_or_create_ed25519("root_license.ed25519.enc", &pass)
        .map_err(|_| AppError::internal("failed to open root license key"))?;

    // license document (mirror CLI)
    #[derive(Serialize)] 
    struct License<'a> { 
        owner: Owner<'a>, 
        loa: &'a str, 
        #[serde(rename = "issuedAt")]
        issued_at: String, 
        #[serde(rename = "expiresAt")]
        expires_at: &'a str, 
        bindings: Bindings<'a> 
    }
    
    #[derive(Serialize)] 
    struct Owner<'a> { 
        id: &'a str, 
        name: &'a str 
    }
    
    #[derive(Serialize)] 
    struct Bindings<'a> { 
        #[serde(rename = "runtimeId")]
        runtime_id: &'a str, 
        #[serde(rename = "canonFingerprint")]
        canon_fingerprint: &'a str 
    }
    
    #[derive(Serialize)] 
    struct Seal<'a> { 
        alg: &'a str, 
        sig: String, 
        pubkey: String, 
        #[serde(rename = "contentHash")]
        content_hash: String 
    }
    
    #[derive(Serialize)] 
    struct Sealed<'a> { 
        license: License<'a>, 
        seal: Seal<'a> 
    }

    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    let lic = License {
        owner: Owner { id: &req.owner_id, name: &req.owner_name },
        loa: &req.loa,
        issued_at: now,
        expires_at: &req.expires_at,
        bindings: Bindings { 
            runtime_id: &runtime_id, 
            canon_fingerprint: &canon_fp 
        },
    };

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
        .map_err(|_| AppError::internal("toml serialization error"))?;
    
    // persist for ops audit / distribution
    let out_dir = PathBuf::from(&st.license_dir);
    tokio::fs::create_dir_all(&out_dir).await.ok();
    let fname = format!("{}_{}.toml", req.owner_id, req.loa);
    let fpath = out_dir.join(fname);
    tokio::fs::write(&fpath, &toml_str).await
        .map_err(|_| AppError::internal("write license failed"))?;

    // also write an audit record in system space (requires quorum later if you enforce)
    st.audit_license_issued(&req.owner_id, &req.loa).await.ok();

    Ok((StatusCode::OK, Json(CreateLicenseResponse {
        file_path: fpath.display().to_string(),
        toml: toml_str,
    })))
}
