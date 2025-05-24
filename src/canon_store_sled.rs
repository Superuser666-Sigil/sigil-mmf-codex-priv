use sled::Db;
use chrono::Utc;
use serde_json;
use sha2::{Sha256, Digest};
use std::fs::{OpenOptions, File};
use std::io::{BufRead, BufReader, Write};
use std::sync::Mutex;
use serde::{Serialize, Deserialize};

use crate::canon_store::{CanonStore, CanonStoreError, CanonStoreResult};
use crate::loa::{LOA, can_read_canon, can_write_canon};
use crate::trusted_knowledge::TrustedKnowledgeEntry;
use crate::audit::{AuditEvent, LogLevel};
use crate::sigil_encrypt::{encrypt, decrypt, decode_base64_key};

/// Global mutex to protect audit log writes from concurrency race conditions.
static AUDIT_LOCK: Mutex<()> = Mutex::new(());

/// A structured, hash-linked line representing a canonical audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoggedAuditLine {
    line: String,
    hash: String,
    prev_hash: Option<String>,
}

/// Retrieve the last hash from the structured audit log file for chaining purposes.
fn read_last_hash(log_path: &str) -> Option<String> {
    let file = File::open(log_path).ok()?;
    let reader = BufReader::new(file);
    let last_line = reader.lines().filter_map(Result::ok).last()?;
    let parsed: Result<LoggedAuditLine, _> = serde_json::from_str(&last_line);
    parsed.ok().map(|r| r.hash)
}

/// Write a structured, hash-linked audit log entry to disk.
fn emit_structured_audit(log_path: &str, line: &str, prev_hash: Option<String>) -> std::io::Result<()> {
    let mut hasher = Sha256::new();
    if let Some(prev) = &prev_hash {
        hasher.update(prev.as_bytes());
    }
    hasher.update(line.as_bytes());
    let hash = format!("{:x}", hasher.finalize());

    let record = LoggedAuditLine {
        line: line.to_string(),
        hash,
        prev_hash,
    };

    let json_line = serde_json::to_string(&record)?;
    let mut file = OpenOptions::new().create(true).append(true).open(log_path)?;
    writeln!(file, "{}", json_line)?;
    Ok(())
}

/// A sled-backed implementation of CanonStore with optional encryption and canonical audit logging.
pub struct CanonStoreSled {
    db: Db,
    allow_operator_write: bool,
    encryption_key: Option<[u8; 32]>,
}

impl CanonStoreSled {
    /// Constructs a new CanonStoreSled instance with the given sled path, write permissions, and optional encryption key.
    pub fn new(path: &str, allow_operator_write: bool, encryption_key_b64: Option<&str>) -> Self {
        let db = sled::open(path).unwrap_or_else(|e| {
            eprintln!("Failed to open sled DB at {}: {}", path, e);
            panic!("Critical: Unable to open DB");
        });

        let encryption_key = encryption_key_b64.and_then(|k| decode_base64_key(k).ok());

        CanonStoreSled {
            db,
            allow_operator_write,
            encryption_key,
        }
    }

    fn serialize_entry(entry: &TrustedKnowledgeEntry) -> Result<Vec<u8>, CanonStoreError> {
        serde_json::to_vec(entry).map_err(|e| CanonStoreError::Serialization(e.to_string()))
    }

    fn deserialize_entry(bytes: &[u8]) -> Result<TrustedKnowledgeEntry, CanonStoreError> {
        serde_json::from_slice(bytes).map_err(|e| CanonStoreError::Deserialization(e.to_string()))
    }

    fn encrypt_if_needed(&self, data: &[u8]) -> CanonStoreResult<Vec<u8>> {
        if let Some(key) = self.encryption_key {
            encrypt(data, key).map_err(|e| CanonStoreError::Encryption(e.to_string()))
        } else {
            Ok(data.to_vec())
        }
    }

    fn decrypt_if_needed(&self, data: &[u8]) -> CanonStoreResult<Vec<u8>> {
        if let Some(key) = self.encryption_key {
            decrypt(data, key).map_err(|e| CanonStoreError::Decryption(e.to_string()))
        } else {
            Ok(data.to_vec())
        }
    }

    fn tree(&self) -> CanonStoreResult<sled::Tree> {
        self.db.open_tree("canon").map_err(|e| {
            CanonStoreError::Database(format!("Failed to open canon tree: {}", e))
        })
    }

    fn log_audit(&self, action: &str, id: &str, loa: &LOA, level: LogLevel) {
        let event = AuditEvent {
            timestamp: Utc::now(),
            action: action.to_string(),
            id: id.to_string(),
            loa: loa.clone(),
            level,
        };
        event.emit(); // emit logs via audit interface
    }
}

impl CanonStore for CanonStoreSled {
    /// Writes a knowledge entry to Canon, applies encryption if configured, and emits a verifiable audit record.
    fn write(&self, id: &str, entry: &TrustedKnowledgeEntry, loa: &LOA) -> CanonStoreResult<()> {
        if !can_write_canon(loa, self.allow_operator_write) {
            return Err(CanonStoreError::PermissionDenied(id.to_string()));
        }

        let data = Self::serialize_entry(entry)?;
        let encrypted = self.encrypt_if_needed(&data)?;
        let tree = self.tree()?;
        tree.insert(id.as_bytes(), encrypted)?;
        tree.flush()?;

        let summary = format!("{}:{}:{}", entry.category, entry.key, entry.content.len());
        {
            let _guard = AUDIT_LOCK.lock().unwrap();
            let last_hash = read_last_hash("audit_log.jsonl");
            if let Err(e) = emit_structured_audit("audit_log.jsonl", &summary, last_hash) {
                eprintln!("[AUDIT-ERROR] Structured audit write failed: {}", e);
            }
        }

        self.log_audit("canon_write", id, loa, LogLevel::Info);
        Ok(())
    }

    /// Reads a Canon entry, decrypts it if needed, and performs LOA validation.
    fn read(&self, id: &str, loa: &LOA) -> CanonStoreResult<Option<TrustedKnowledgeEntry>> {
        if !can_read_canon(loa) {
            return Err(CanonStoreError::PermissionDenied(id.to_string()));
        }

        let tree = self.tree()?;
        match tree.get(id.as_bytes())? {
            Some(bytes) => {
                let decrypted = self.decrypt_if_needed(&bytes)?;
                let entry = Self::deserialize_entry(&decrypted)?;
                self.log_audit("canon_read", id, loa, LogLevel::Info);
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }
}
