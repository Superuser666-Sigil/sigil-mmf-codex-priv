// Canonical verifier patch with LOA lineage enforcement
use crate::audit::{AuditEvent, LogLevel};
use crate::loa::LOA;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditLineHash {
    pub line: String, // stringified AuditEvent
    pub hash: String,
    pub previous: Option<String>,
}

#[derive(Debug)]
pub enum AuditVerifyError {
    InvalidHash,
    Unauthorized,
    MalformedLine(usize),
    IOError(std::io::Error),
}

pub enum VerificationStatus {
    Verified,
    HashMismatch,
    Malformed,
    UnauthorizedEmitter,
    IOError,
}

pub trait AuditVerifyAccess {
    fn can_verify_audit(&self) -> bool;
}

impl AuditVerifyAccess for LOA {
    fn can_verify_audit(&self) -> bool {
        matches!(self, LOA::Mentor | LOA::Root)
    }
}

pub fn verify_audit_stream<T: AuditVerifyAccess, R: BufRead>(
    loa: &T,
    reader: R
) -> Result<Vec<VerificationStatus>, AuditVerifyError> {
    if !loa.can_verify_audit() {
        return Err(AuditVerifyError::Unauthorized);
    }

    let mut statuses = Vec::new();
    let mut previous_hash: Option<String> = None;

    for (i, line) in reader.lines().enumerate() {
        let raw = line.map_err(AuditVerifyError::IOError)?;
        let logged: AuditLineHash = serde_json::from_str(&raw)
            .map_err(|_| AuditVerifyError::MalformedLine(i + 1))?;

        // Deserialize the inner audit line to validate emitter's LOA
        let audit_event: AuditEvent = serde_json::from_str(&logged.line)
            .map_err(|_| AuditVerifyError::MalformedLine(i + 1))?;

        if let Some(event_loa) = &audit_event.loa {
            if !matches!(loa_can_validate(loa, event_loa), Ok(true)) {
                statuses.push(VerificationStatus::UnauthorizedEmitter);
                continue;
            }
        }

        let expected = compute_hash(&logged.line, logged.previous.as_deref());

        if expected == logged.hash {
            statuses.push(VerificationStatus::Verified);
        } else {
            statuses.push(VerificationStatus::HashMismatch);
        }

        previous_hash = Some(logged.hash.clone());
    }

    Ok(statuses)
}

fn loa_can_validate<T: AuditVerifyAccess>(verifier: &T, emitter: &LOA) -> Result<bool, AuditVerifyError> {
    // Implicit Root bypass
    if let Some(root) = verifier.downcast_ref::<LOA>() {
        if matches!(root, LOA::Root) { return Ok(true); }
        if root >= emitter { return Ok(true); }
    }
    Ok(false)
}

pub fn compute_hash(line: &str, previous: Option<&str>) -> String {
    use sha2::{Digest, Sha256};
    let base = match previous {
        Some(prev) => format!("{}{}", prev, line),
        None => line.to_string()
    };
    format!("{:x}", Sha256::digest(base.as_bytes()))
}

pub fn verify_audit_file<T: AuditVerifyAccess>(loa: &T, path: &str) -> Result<Vec<VerificationStatus>, AuditVerifyError> {
    let file = File::open(path).map_err(AuditVerifyError::IOError)?;
    let reader = BufReader::new(file);
    verify_audit_stream(loa, reader)
}
