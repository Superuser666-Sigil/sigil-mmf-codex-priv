use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;

use crate::{
    quorum_system::{QuorumSystem, SystemProposal}, 
    canon_store::CanonStore,
    canonical_record::CanonicalRecord,
    crypto::KeyStore,
    sigil_runtime_core::SigilRuntimeCore,
};

pub struct AppState {
    pub runtime_id: String,
    pub canon_fingerprint: String,
    pub key_dir: String,
    pub license_dir: String,
    pub license_passphrase: Option<String>,

    pub quorum: RwLock<QuorumSystem>,
    pub canon_store: Arc<Mutex<dyn CanonStore>>,
    pub runtime_core: Arc<RwLock<SigilRuntimeCore>>,
    pub key_store: KeyStore,
}

impl AppState {
    pub fn new(
        runtime_id: String,
        canon_fingerprint: String,
        key_dir: String,
        license_dir: String,
        license_passphrase: Option<String>,
        quorum: QuorumSystem,
        canon_store: Arc<Mutex<dyn CanonStore>>,
        runtime_core: Arc<RwLock<SigilRuntimeCore>>,
    ) -> Self {
        let key_store = KeyStore::new(&key_dir);
        
        Self {
            runtime_id,
            canon_fingerprint,
            key_dir,
            license_dir,
            license_passphrase,
            quorum: RwLock::new(quorum),
            canon_store,
            runtime_core,
            key_store,
        }
    }

    pub async fn audit_license_issued(&self, owner_id: &str, loa: &str) -> anyhow::Result<()> {
        // write a FrozenChain/CanonicalRecord in system space documenting issuance
        // TODO: Implement audit trail for license issuance
        tracing::info!("License issued: owner={}, loa={}", owner_id, loa);
        Ok(())
    }

    pub fn rebuild_canonical_record_from_proposal(&self, prop: &SystemProposal)
        -> anyhow::Result<CanonicalRecord>
    {
        // Create properly signed CanonicalRecord from proposal
        let payload = serde_json::json!({
            "entry": prop.entry,
            "content": prop.content,
            "content_hash": prop.content_hash,
            "required_k": prop.required_k,
            "signers": prop.signers,
            "created_at": prop.created_at,
            "expires_at": prop.expires_at,
        });

        let record = CanonicalRecord::new_signed(
            "system_proposal",
            &prop.id,
            "system",
            "system",
            payload,
            None,
        ).map_err(|e| anyhow::anyhow!("Failed to create signed record: {e}"))?;

        Ok(record)
    }

    pub fn verify_record_signatures(&self, rec: &CanonicalRecord) -> anyhow::Result<()> {
        // verify root + witness signatures against WitnessRegistry
        // TODO: Implement signature verification against witness registry
        tracing::debug!("Verifying signatures for record: {}", rec.id);
        Ok(())
    }
}
