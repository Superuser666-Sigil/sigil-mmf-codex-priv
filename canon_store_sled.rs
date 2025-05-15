// CanonStoreSled.rs - Unified Canon Store (Plaintext + Encrypted)
// Purpose: Sled-backed implementation of CanonStore with optional encryption, full audit, IRL traceability

use sled::Db;
use serde_json;
use chrono::Utc;

use crate::canon_store::{CanonStore, CanonStoreError, CanonStoreResult};
use crate::loa::{LOA, can_read_canon, can_write_canon};
use crate::trusted_knowledge::{TrustedKnowledgeEntry, SigilVerdict};
use crate::audit::{AuditEvent, LogLevel};
use crate::sigil_encrypt::{encrypt, decrypt, decode_base64_key};

pub struct CanonStoreSled {
    db: Db,
    allow_operator_write: bool,
    encryption_key: Option<[u8; 32]>,
}

impl CanonStoreSled {
    pub fn new(path: &str, allow_operator_write: bool, encryption_key_b64: Option<&str>) -> Self {
        let db = sled::open(path).unwrap_or_else(|e| {
            eprintln!("Failed to open sled DB at {}: {}", path, e);
            panic!("Critical: Unable to open DB");
        });

        let encryption_key = encryption_key_b64
            .and_then(|k| decode_base64_key(k).ok());

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
        event.emit(); // emit logs via crate::audit
    }
}

impl CanonStore for CanonStoreSled {
    fn write(&self, id: &str, entry: &TrustedKnowledgeEntry, loa: &LOA) -> CanonStoreResult<()> {
        if !can_write_canon(loa, self.allow_operator_write) {
            return Err(CanonStoreError::PermissionDenied(id.to_string()));
        }

        let data = Self::serialize_entry(entry)?;
        let encrypted = self.encrypt_if_needed(&data)?;
        let tree = self.tree()?;

        tree.insert(id.as_bytes(), encrypted)?;
        tree.flush()?;

        self.log_audit("canon_write", id, loa, LogLevel::Info);
        Ok(())
    }

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
