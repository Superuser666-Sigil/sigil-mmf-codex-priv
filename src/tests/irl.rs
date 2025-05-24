// tests/irl.rs
use mmf_sigil::irl_runtime::{TrustGuard, TrustVerdict};
use mmf_sigil::trusted_knowledge::TrustedKnowledgeEntry;
use mmf_sigil::canon_store::{CanonStore, CanonStoreResult};
use mmf_sigil::canon_store_sled::CanonStoreSled;
use mmf_sigil::session_context::SessionContext;
use mmf_sigil::loa::LOA;

use tempfile::tempdir;
use std::sync::{Arc, RwLock};

#[test]
pub fn irl_enforces_stored_verdict() -> CanonStoreResult<()> {
    let dir = tempdir()?;
    let path = dir.path().to_str().unwrap();

    let store = CanonStoreSled::new(path, true, None);
    let id = "unit_subject";

    let entry = TrustedKnowledgeEntry {
        model_id: Some("mock_model".to_string()),
        allowed: true,
        score: 0.93,
        threshold: Some(0.75),
        trace_id: Some("unit-trace".to_string()),
    };

    store.write(id, &entry, &LOA::Root)?;

    let ctx = SessionContext::bootstrap().expect("Failed to bootstrap session");

    let verdict = TrustGuard::enforce(id, &store, &ctx)?;
    assert!(verdict.allowed);
    assert!(verdict.score > 0.9);
    assert_eq!(verdict.trace_id.as_deref(), Some("unit-trace"));

    Ok(())
}

#[test]
pub fn irl_rejects_unknown_id() {
    let dir = tempdir().unwrap();
    let path = dir.path().to_str().unwrap();
    let store = CanonStoreSled::new(path, true, None);

    let ctx = SessionContext::bootstrap().expect("bootstrap");

    let result = TrustGuard::enforce("nonexistent", &store, &ctx);
    assert!(result.is_err());
}