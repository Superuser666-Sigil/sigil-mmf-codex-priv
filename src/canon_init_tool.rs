
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use crate::canon_store::CanonStore;
use crate::canon_store_sled::CanonStoreSled;
use crate::config_loader::load_config;
use crate::license_validator::validate_license;
use crate::session_context::SessionContext;
use crate::trusted_knowledge::{TrustedKnowledgeEntry, SigilVerdict};
use crate::audit::AuditEvent;
use crate::loa::LOA;

use serde_json;

pub fn run_loader(file_path: &str, license_token: &str) -> Result<(), String> {
    let config = load_config();
    let session = Arc::new(SessionContext::new(config.clone(), Some(license_token)));

    if session.loa != LOA::Root {
        return Err("LOA::Root required to run canon_init_tool.".into());
    }

    let mut file = File::open(Path::new(file_path)).map_err(|_| "Unable to open canon data file")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).map_err(|_| "Failed to read file")?;

    let entries: Vec<TrustedKnowledgeEntry> = serde_json::from_str(&contents).map_err(|_| "Invalid canon file format")?;
    let mut store = CanonStoreSled::new("data/canon", config.trust.allow_operator_canon_write);

    for mut entry in entries {
        entry.verdict = SigilVerdict::Allow;
        let audit = AuditEvent::new(
            &session.log_identity(),
            "canon_init",
            Some(&entry.id),
            &session.session_id,
            &session.loa,
        );
        audit.write_to_log("logs/audit_access_log.jsonl").ok();

        store.add_entry(entry, &session.loa, config.trust.allow_operator_canon_write)
            .map_err(|e| format!("Canon entry write failed: {}", e))?;
    }

    println!("[SigilInit] Canon entries loaded successfully.");
    Ok(())
}
