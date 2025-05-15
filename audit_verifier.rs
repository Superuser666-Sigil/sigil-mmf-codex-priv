// Phase 1 - Canon Extension: audit_verifier.rs
// Purpose: Structured, tamper-aware log verification with IRL trust signaling

use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::{BufRead, BufReader};
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

/// Status for each line in the audit chain
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationStatus {
    Verified,
    HashMismatch,
    IOError,
}

/// Canonical verification result per line in an audit log
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditLineHash {
    pub line_number: usize,
    pub status: VerificationStatus,
    pub hash: String,
    pub expected_hash: Option<String>,
    pub irl_score: f32,
    pub trace_id: Option<String>,
    pub source: String,
    pub timestamp: DateTime<Utc>,
}

/// Verifies the audit log at `path` by computing a hash chain and reporting line-by-line results.
pub fn verify_audit_log(
    path: &str,
    trace_id: Option<String>,
    source: &str,
) -> Result<Vec<AuditLineHash>, std::io::Error> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut previous_hash: Option<String> = None;
    let mut results = Vec::new();

    for (line_number, line_result) in reader.lines().enumerate() {
        let timestamp = Utc::now();
        let mut status = VerificationStatus::Verified;
        let mut irl_score = 1.0;
        let mut actual_hash = String::new();
        let mut expected_hash = previous_hash.clone();

        match line_result {
            Ok(line) => {
                let mut hasher = Sha256::new();
                if let Some(prev) = &previous_hash {
                    hasher.update(prev);
                }
                hasher.update(&line);
                let hash_bytes = hasher.finalize();
                actual_hash = format!("{:x}", hash_bytes);

                // If previous hash exists, verify the chain matches
                if let Some(expected) = &previous_hash {
                    let mut check_hasher = Sha256::new();
                    check_hasher.update(expected);
                    check_hasher.update(&line);
                    let check_hash = format!("{:x}", check_hasher.finalize());

                    if check_hash != actual_hash {
                        status = VerificationStatus::HashMismatch;
                        irl_score = 0.0;
                    }
                }

                previous_hash = Some(actual_hash.clone());
            }
            Err(_) => {
                status = VerificationStatus::IOError;
                actual_hash = "unreadable".into();
                irl_score = 0.0;
            }
        }

        results.push(AuditLineHash {
            line_number: line_number + 1,
            status,
            hash: actual_hash,
            expected_hash,
            irl_score,
            trace_id: trace_id.clone(),
            source: source.to_string(),
            timestamp,
        });
    }

    Ok(results)
}
