use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use crate::audit::AuditEvent;
use crate::canon_store::CanonStore;
use crate::canon_store_sled_encrypted::CanonStoreSled as EncryptedCanonStoreSled;
use crate::keys::KeyManager;
use crate::canonical_record::CanonicalRecord;
use crate::config_loader::load_config;
use crate::loa::LOA;
use crate::session_context::SessionContext;
use crate::trusted_knowledge::{SigilVerdict, TrustedKnowledgeEntry};

use serde_json;

pub fn run_loader(file_path: &str, license_token: &str) -> Result<(), String> {
    let config = load_config().map_err(|e| format!("Failed to load config: {e}"))?;
    let loa = LOA::from_str(license_token).unwrap_or(LOA::Guest);
    let session = Arc::new(SessionContext::new("canon_init_session", loa));

    if session.loa != LOA::Root {
        return Err("LOA::Root required to run canon_init_tool.".into());
    }

    let mut file =
        File::open(Path::new(file_path)).map_err(|_| "Unable to open canon data file")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|_| "Failed to read file")?;

    let entries: Vec<TrustedKnowledgeEntry> =
        serde_json::from_str(&contents).map_err(|_| "Invalid canon file format")?;
    // Use encrypted Sled backend and managed encryption key
    let enc_key = KeyManager::get_encryption_key()
        .map_err(|_| "Failed to get encryption key for canon store")?;
    let mut store = EncryptedCanonStoreSled::new("data/canon", &enc_key)
        .map_err(|_| "Failed to create encrypted canon store")?;

    for mut entry in entries {
        // Force verdict to Allow for imported entries
        entry.verdict = SigilVerdict::Allow;
        // Build an audit event for logging
        let audit = AuditEvent::new(
            "canon_init_tool",
            "canon_init",
            Some(&entry.id),
            &session.session_id,
            &session.loa,
        );
        audit.write_to_log().ok();

        // Convert to canonical record with tenant "system" and space "system"
        let record = CanonicalRecord::from_trusted_entry(&entry, "system", "system", 1)
            .map_err(|e| format!("Failed to create canonical record: {e}"))?;

        store
            .add_record(
                record,
                &session.loa,
                config.trust.allow_operator_canon_write,
            )
            .map_err(|e| format!("Canon record write failed: {e}"))?;
    }

    println!("[SigilInit] Canon entries loaded successfully.");
    Ok(())
}
