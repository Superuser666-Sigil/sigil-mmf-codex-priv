use crate::canon_loader::load_canon_entries;
use crate::canon_validator::validate_entry;
use crate::irl_executor::evaluate_with_irl;
use crate::audit::log_audit_event;
use crate::trusted_knowledge::TrustedKnowledgeEntry;
use chrono::Utc;

pub fn run_sigil_session(canon_path: &str) {
    match load_canon_entries(canon_path) {
        Ok(entries) => {
            for (i, entry) in entries.iter().enumerate() {
                let result = validate_entry(entry);
                match result {
                    Ok(_) => {
                        println!("Canon entry [{}] validated successfully.", i);
                        match evaluate_with_irl(entry) {
                            Ok(score) => println!("IRL score: {:.2}", score),
                            Err(e) => eprintln!("IRL scoring failed: {}", e),
                        }
                    },
                    Err(e) => {
                        eprintln!("Validation failed on entry [{}]: {}", i, e);
                        log_audit_event("ValidationFailed", Some(&entry.id), &format!("{}", e), "Error", Utc::now());
                    }
                }
            }
        },
        Err(e) => {
            eprintln!("Canon load error: {}", e);
            log_audit_event("CanonLoadFailure", None, &e, "Critical", Utc::now());
        }
    }
}
