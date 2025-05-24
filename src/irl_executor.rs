use crate::trusted_knowledge::TrustedKnowledgeEntry;
use crate::irl_data_pipeline::score_entry;
use crate::irl_telemetry::log_irl_result;
use crate::audit::log_audit_event;
use chrono::Utc;

pub fn evaluate_with_irl(entry: &TrustedKnowledgeEntry) -> Result<f32, String> {
    match score_entry(entry) {
        Ok(score) => {
            log_irl_result(&entry.id, score);
            log_audit_event("IRLScoreGenerated", Some(&entry.id), &format!("Score: {}", score), "Info", Utc::now());
            Ok(score)
        },
        Err(e) => {
            log_audit_event("IRLScoreFailure", Some(&entry.id), &e, "Warning", Utc::now());
            Err(e)
        }
    }
}
