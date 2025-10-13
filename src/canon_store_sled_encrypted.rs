use crate::audit::{AuditEvent, LogLevel};
use crate::canon_store::CanonStore;
use crate::canonical_record::CanonicalRecord;
use crate::loa::{LOA, can_read_canon, can_write_canon};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use chrono::{DateTime, Utc};
use ed25519_dalek::Verifier;
use serde_json;
use sha2::Digest;
use sled::Db;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Database audit event for tracking access
#[derive(Debug, Clone)]
pub struct DatabaseAuditEvent {
    pub timestamp: DateTime<Utc>,
    pub user_id: String,
    pub operation: String,
    pub resource: String,
    pub success: bool,
}

/// Database access control for security
pub struct DatabaseAccessControl {
    allowed_operations: HashMap<String, Vec<String>>,
    audit_log: Arc<Mutex<Vec<DatabaseAuditEvent>>>,
}

impl Default for DatabaseAccessControl {
    fn default() -> Self {
        Self::new()
    }
}

impl DatabaseAccessControl {
    pub fn new() -> Self {
        Self {
            allowed_operations: HashMap::new(),
            audit_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn can_perform_operation(&self, user_id: &str, operation: &str, _resource: &str) -> bool {
        if let Some(allowed_ops) = self.allowed_operations.get(user_id) {
            allowed_ops.contains(&operation.to_string())
        } else {
            false
        }
    }

    pub fn log_operation(&self, user_id: &str, operation: &str, resource: &str, success: bool) {
        let event = DatabaseAuditEvent {
            timestamp: Utc::now(),
            user_id: user_id.to_string(),
            operation: operation.to_string(),
            resource: resource.to_string(),
            success,
        };

        if let Ok(mut log) = self.audit_log.lock() {
            log.push(event);
        }
    }

    pub fn get_audit_log(&self) -> Vec<DatabaseAuditEvent> {
        if let Ok(log) = self.audit_log.lock() {
            log.clone()
        } else {
            Vec::new()
        }
    }
}

pub struct CanonStoreSled {
    db: Db,
    encryption_key: [u8; 32],
    access_control: DatabaseAccessControl,
}

impl CanonStoreSled {
    pub fn new(path: &str, encryption_key: &[u8; 32]) -> Result<Self, String> {
        let db = sled::open(path).map_err(|e| format!("Failed to open sled database: {e}"))?;

        // Verify encryption key is set
        if encryption_key.iter().all(|&b| b == 0) {
            return Err("Encryption key cannot be all zeros".to_string());
        }

        Ok(Self {
            db,
            encryption_key: *encryption_key,
            access_control: DatabaseAccessControl::new(),
        })
    }

    fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
        use rand::RngCore;

        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|e| format!("Invalid encryption key: {e}"))?;

        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);

        let encrypted = cipher
            .encrypt(&nonce.into(), data)
            .map_err(|e| format!("Encryption failed: {e}"))?;

        let mut result = nonce.to_vec();
        result.extend_from_slice(&encrypted);
        Ok(result)
    }

    fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, String> {
        use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};

        if encrypted_data.len() < 12 {
            return Err("Invalid encrypted data format".to_string());
        }

        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|e| format!("Invalid encryption key: {e}"))?;

        let nonce = &encrypted_data[..12];
        let data = &encrypted_data[12..];

        cipher
            .decrypt(nonce.into(), data)
            .map_err(|e| format!("Decryption failed: {e}"))
    }

    fn verify_record_integrity(record: &CanonicalRecord) -> Result<(), &'static str> {
        // Basic presence checks
        if record.hash.is_empty() {
            return Err("missing hash");
        }
        let sig_b64 = record.sig.as_ref().ok_or("missing signature")?;
        let pk_b64 = record.pub_key.as_ref().ok_or("missing public key")?;

        // Recompute canonical JSON and hash
        let canonical_json = record
            .to_canonical_json()
            .map_err(|_| "canonicalization failed")?;
        let recomputed = sha2::Sha256::digest(canonical_json.as_bytes());
        let recomputed_hex = hex::encode(recomputed);
        if recomputed_hex != record.hash {
            return Err("hash mismatch");
        }

        // Decode signature and public key
        let sig_bytes = B64.decode(sig_b64).map_err(|_| "invalid signature b64")?;
        if sig_bytes.len() != 64 {
            return Err("invalid signature length");
        }
        let signature = ed25519_dalek::Signature::from_bytes(
            sig_bytes.as_slice().try_into().map_err(|_| "sig bytes")?,
        );

        let pk_bytes = B64.decode(pk_b64).map_err(|_| "invalid pubkey b64")?;
        if pk_bytes.len() != 32 {
            return Err("invalid pubkey length");
        }
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
            pk_bytes.as_slice().try_into().map_err(|_| "pk bytes")?,
        )
        .map_err(|_| "invalid verifying key")?;

        // Accept signature either over canonical json bytes (preferred) or over the hash bytes (compat)
        let mut ok = verifying_key
            .verify(canonical_json.as_bytes(), &signature)
            .is_ok();
        if !ok && let Ok(hash_bytes) = hex::decode(&record.hash) {
            ok = verifying_key.verify(&hash_bytes, &signature).is_ok();
        }
        if !ok {
            return Err("signature verification failed");
        }
        Ok(())
    }
}

impl CanonStore for CanonStoreSled {
    fn load_record(&self, key: &str, loa: &LOA) -> Option<CanonicalRecord> {
        if !can_read_canon(loa) {
            return None;
        }
        // Log access attempt
        let user_id = format!("loa_{loa:?}");
        self.access_control
            .log_operation(&user_id, "read", key, true);
        self.db.get(key).ok().flatten().and_then(|ivec| {
            let data = match self.decrypt_data(&ivec) {
                Ok(decrypted) => decrypted,
                Err(_) => ivec.to_vec(),
            };
            serde_json::from_slice::<CanonicalRecord>(&data).ok()
        })
    }

    fn add_record(
        &mut self,
        record: CanonicalRecord,
        loa: &LOA,
        _allow_operator_write: bool,
    ) -> Result<(), &'static str> {
        if !can_write_canon(loa) {
            return Err("Insufficient LOA to write canon record");
        }
        // Enforce sign-on-write integrity checks
        Self::verify_record_integrity(&record)?;
        let user_id = format!("loa_{loa:?}");
        self.access_control
            .log_operation(&user_id, "write", &record.id, true);
        let serialized = serde_json::to_vec(&record).map_err(|_| "Serialization failed")?;
        let encrypted = self
            .encrypt_data(&serialized)
            .map_err(|_| "Canon encryption failed")?;
        self.db
            .insert(record.id.as_str(), encrypted)
            .map_err(|_| "Write failed")?;
        // Flush to ensure durability
        self.db.flush().map_err(|_| "Flush failed")?;

        // Audit hook (best-effort)
        let _ = AuditEvent::new(
            &user_id,
            "canon_write",
            Some(&record.id),
            "canon_store",
            loa,
        )
        .with_severity(LogLevel::Info)
        .write_to_log();
        Ok(())
    }

    fn list_records(&self, kind: Option<&str>, loa: &LOA) -> Vec<CanonicalRecord> {
        if !can_read_canon(loa) {
            return vec![];
        }
        self.db
            .iter()
            .filter_map(|item| item.ok())
            .filter_map(|(_, val)| match self.decrypt_data(&val) {
                Ok(decrypted) => serde_json::from_slice::<CanonicalRecord>(&decrypted).ok(),
                Err(_) => serde_json::from_slice::<CanonicalRecord>(&val).ok(),
            })
            .filter(|record| kind.is_none() || kind.map(|k| record.kind == k).unwrap_or(false))
            .collect()
    }
}
