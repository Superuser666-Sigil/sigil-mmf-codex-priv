use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use crate::audit::{AuditEvent, emit_audit, LogLevel};
use crate::loa::LOA;
use crate::trusted_knowledge::TrustedKnowledgeEntry;
use crate::trusted_knowledge::CanonNode;

#[derive(Debug, Serialize, Deserialize)]
pub struct CanonRevision {
    pub revision_id: String,
    pub parent_hash: Option<String>,
    pub timestamp: chrono::DateTime<Utc>,
    pub editor: String,
    pub loa: LOA,
    pub reason: Option<String>,
    pub irl_score: f32,
    pub canon_node: CanonNode,
}

pub fn commit_revision(
    new_entry: &CanonNode,
    previous_content: Option<&CanonNode>,
    editor: &str,
    loa: LOA,
    reason: Option<String>,
    irl_score: f32,
) -> CanonRevision {
    let timestamp = Utc::now();

    let serialized = serde_json::to_string(new_entry)
        .expect("Failed to serialize CanonNode for hashing");
    let current_hash = format!("{:x}", Sha256::digest(serialized.as_bytes()));

    let parent_hash = previous_content.map(|prev| {
        let prev_serialized = serde_json::to_string(prev)
            .expect("Failed to serialize previous CanonNode");
        format!("{:x}", Sha256::digest(prev_serialized.as_bytes()))
    });

    if let Some(prev_hash) = &parent_hash {
        if prev_hash == &current_hash {
            emit_audit(
                AuditEvent::new(
                    editor,
                    "canon_revision_skipped (identical)",
                    &new_entry.id,
                    "canon_diff_chain.rs"
                ).with_loa(loa)
                 .with_context("Skipped revision: content identical".into())
                 .with_severity(LogLevel::Info)
            );
            panic!("No change detected in CanonNode; revision aborted.");
        }
    }

    let revision = CanonRevision {
        revision_id: Uuid::new_v4().to_string(),
        parent_hash,
        timestamp,
        editor: editor.to_string(),
        loa,
        reason: reason.clone(),
        irl_score,
        canon_node: new_entry.clone(),
    };

    let audit_msg = format!(
        "Committed Canon revision for '{}'. Reason: {}",
        revision.canon_node.name,
        reason.unwrap_or_else(|| "<unspecified>".into())
    );

    emit_audit(
        AuditEvent::new(
            editor,
            "canon_revision_committed",
            &revision.canon_node.id,
            "canon_diff_chain.rs"
        ).with_loa(loa)
         .with_context(audit_msg)
         .with_severity(LogLevel::Info)
    );

    revision
}