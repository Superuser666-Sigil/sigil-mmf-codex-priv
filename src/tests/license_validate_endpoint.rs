use axum::{Router, body::Body, extract::Request, http::StatusCode};
use std::sync::{Arc, RwLock};
use tower::ServiceExt;

use crate::runtime_config::RuntimeConfig;
use crate::sigil_runtime_core::SigilRuntimeCore;
use crate::loa::LOA;
use crate::canon_store::CanonStore;
use crate::canon_store_sled_encrypted::CanonStoreSled as EncryptedCanonStoreSled;
use crate::keys::KeyManager;

fn build_app() -> (Router<Arc<crate::app_state::AppState>>, tempfile::TempDir, String, String) {
    use tempfile::TempDir;
    use std::sync::Mutex;
    use crate::witness_registry::WitnessRegistry;
    use crate::quorum_system::QuorumSystem;
    use crate::app_state::AppState;

    let temp_dir = TempDir::new().unwrap();
    let store_path = temp_dir.path().to_str().unwrap().to_string();
    let encryption_key = KeyManager::dev_key_for_testing().unwrap();
    let store_impl = EncryptedCanonStoreSled::new(&store_path, &encryption_key).unwrap();
    let canon_store: Arc<Mutex<dyn CanonStore>> = Arc::new(Mutex::new(store_impl));

    let runtime_id = "test-runtime-id".to_string();
    let canon_fp = "sha256:test-fingerprint".to_string();

    let runtime = SigilRuntimeCore::new(
        LOA::Observer,
        canon_store.clone(),
        RuntimeConfig::default(),
    ).unwrap();
    let runtime_core = Arc::new(RwLock::new(runtime));

    let witness_registry = Arc::new(WitnessRegistry::new(canon_store.clone()).unwrap());
    let quorum = QuorumSystem::new(witness_registry);

    let app_state = Arc::new(AppState::new(
        runtime_id.clone(),
        canon_fp.clone(),
        temp_dir.path().to_string_lossy().to_string(),
        temp_dir.path().to_string_lossy().to_string(),
        Some("testpass".to_string()),
        quorum,
        canon_store,
        runtime_core,
    ));

    let app = crate::enhanced_web::build_enhanced_router(app_state.clone());
    (app, temp_dir, runtime_id, canon_fp)
}

fn make_legacy_license(runtime_id: &str, canon_fp: &str, loa: &str) -> String {
    use chrono::{Utc, Duration};
    let now = Utc::now();
    let expires = now + Duration::days(30);
    format!(
        r#"[license]
id = "test.license"
issuedAt = "{}"
expiresAt = "{}"
loa = "{}"
scope = ["*"]
issuer = "test"
version = "1.0"

[license.owner]
name = "Test User"
mnemonic = "test-mnemo"
email = "test@example.com"
hashId = "test_user_id"

[license.bindings]
canonFingerprint = "{}"
runtimeId = "{}"

[license.trust]
trustModel = "quorum"
signature = "FAKESIG"
sealed = true

[license.permissions]
canMutateCanon = false
canOverrideAudit = false
canRegisterModule = true
canElevateIdentity = false

[license.audit]
lastVerified = "{}"
verifier = "test"
canonicalized = true
"#,
        now.to_rfc3339(),
        expires.to_rfc3339(),
        loa,
        canon_fp,
        runtime_id,
        now.to_rfc3339()
    )
}

#[tokio::test]
async fn license_validate_endpoint_accepts_valid_legacy_license() {
    let (app, _tmp, runtime_id, canon_fp) = build_app();
    let lic = make_legacy_license(&runtime_id, &canon_fp, "Operator");
    let body = serde_json::json!({"license_content": lic});

    let req = Request::builder()
        .method("POST")
        .uri("/api/license/validate")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v.get("valid").and_then(|x| x.as_bool()), Some(true));
    assert_eq!(v.get("loa").and_then(|x| x.as_str()), Some("operator"));
    assert_eq!(v.get("owner_id").and_then(|x| x.as_str()), Some("test_user_id"));
}

#[tokio::test]
async fn license_validate_endpoint_rejects_wrong_runtime() {
    let (app, _tmp, _runtime_id, canon_fp) = build_app();
    let lic = make_legacy_license("WRONG_RUNTIME", &canon_fp, "Operator");
    let body = serde_json::json!({"license_content": lic});

    let req = Request::builder()
        .method("POST")
        .uri("/api/license/validate")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v.get("valid").and_then(|x| x.as_bool()), Some(false));
}


