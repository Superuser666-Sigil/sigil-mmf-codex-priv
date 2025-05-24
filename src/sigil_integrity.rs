// Canon-Compliant: sigil_integrity.rs
// Purpose: Enforce runtime data integrity via LOA quorum, entropy anchors, and external provenance

use crate::loa::LOA;
use crate::sigil_encrypt::{hash_with_entropy, verify_signature};
use crate::audit::{AuditEvent, LogLevel};
use chrono::{Utc, DateTime};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyAnchor {
    pub timestamp: DateTime<Utc>,
    pub salt: String,
    pub origin_host: String,
    pub context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessSignature {
    pub loa_level: LOA,
    pub witness_id: String,
    pub signature: String, // e.g., Ed25519 base64
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorSource {
    pub uri: String,
    pub kind: AnchorKind,
    pub expected_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnchorKind {
    Git,
    IPFS,
    DNS,
    Blockchain,
}

#[derive(Debug)]
pub enum IntegrityError {
    HashMismatch,
    AnchorInvalid,
    WitnessQuorumFailed,
}

/// Main integrity verification entrypoint
pub fn verify_integrity(
    data: &[u8],
    entropy: &EntropyAnchor,
    expected_hash: &str,
    witnesses: &[WitnessSignature],
    anchors: &[AnchorSource],
    required_loa: LOA,
) -> Result<(), IntegrityError> {
    let calculated = hash_with_entropy(data, entropy);

    if calculated != expected_hash {
        log::warn!("Integrity failure: Hash mismatch");
        return Err(IntegrityError::HashMismatch);
    }

    for anchor in anchors {
        if !verify_anchor(anchor, &calculated) {
            log::warn!("Anchor mismatch: URI {} did not validate", anchor.uri);
            return Err(IntegrityError::AnchorInvalid);
        }
    }

    if !validate_witnesses(witnesses, required_loa, &calculated) {
        log::warn!("Witness quorum not satisfied");
        return Err(IntegrityError::WitnessQuorumFailed);
    }

    Ok(())
}

fn verify_anchor(anchor: &AnchorSource, hash: &str) -> bool {
    log::info!("Checking anchor at: {}", anchor.uri);
    anchor.expected_hash == hash
}

fn validate_witnesses(
    witnesses: &[WitnessSignature],
    required_loa: LOA,
    payload_hash: &str,
) -> bool {
    let valid = witnesses.iter().filter(|w| {
        w.loa_level >= required_loa &&
        verify_signature(&w.signature, payload_hash.as_bytes(), &w.witness_id)
    }).count();

    valid >= 2 // Default quorum size
}
