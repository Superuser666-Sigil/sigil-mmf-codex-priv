use crate::canon_store::CanonStore;
use crate::loa::{LOA, can_read_canon, can_write_canon};
use crate::trusted_knowledge::TrustedKnowledgeEntry;
use serde_json;
use sled::Db;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc};

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
        let db = sled::open(path)
            .map_err(|e| format!("Failed to open sled database: {e}"))?;
        
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
        
        let encrypted = cipher.encrypt(&nonce.into(), data)
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
        
        cipher.decrypt(nonce.into(), data)
            .map_err(|e| format!("Decryption failed: {e}"))
    }
}

impl CanonStore for CanonStoreSled {
    fn load_entry(&self, key: &str, loa: &LOA) -> Option<TrustedKnowledgeEntry> {
        if !can_read_canon(loa) {
            return None;
        }

        // Log access attempt
        let user_id = format!("loa_{loa:?}");
        self.access_control.log_operation(&user_id, "read", key, true);

        self.db.get(key).ok().flatten().and_then(|ivec| {
            // Use new encryption method
            let data = match self.decrypt_data(&ivec) {
                Ok(decrypted) => decrypted,
                Err(_) => ivec.to_vec(), // Fallback to unencrypted
            };
            serde_json::from_slice::<TrustedKnowledgeEntry>(&data).ok()
        })
    }

    fn add_entry(
        &mut self,
        entry: TrustedKnowledgeEntry,
        loa: &LOA,
        _allow_operator_write: bool,
    ) -> Result<(), &'static str> {
        if !can_write_canon(loa) {
            return Err("Insufficient LOA to write canon entry");
        }

        // Log write attempt
        let user_id = format!("loa_{loa:?}");
        self.access_control.log_operation(&user_id, "write", &entry.id, true);

        let serialized = serde_json::to_vec(&entry).map_err(|_| "Serialization failed")?;
        
        // Always encrypt data for security
        let encrypted = self.encrypt_data(&serialized)
            .map_err(|_| "Canon encryption failed")?;

        self.db
            .insert(entry.id.as_str(), encrypted)
            .map_err(|_| "Write failed")?;
        Ok(())
    }

    fn list_entries(&self, category: Option<&str>, loa: &LOA) -> Vec<TrustedKnowledgeEntry> {
        if !can_read_canon(loa) {
            return vec![];
        }

        self.db
            .iter()
            .filter_map(|item| item.ok())
            .filter_map(|(_, val)| serde_json::from_slice::<TrustedKnowledgeEntry>(&val).ok())
            .filter(|entry| category.is_none_or(|cat| entry.category == cat))
            .collect()
    }
}
