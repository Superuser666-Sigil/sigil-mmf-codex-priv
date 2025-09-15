//! Secure audit chain implementation for cryptographic integrity
//!
//! This module implements cryptographically secure audit trails
//! as specified in Phase 2.5 of the security audit plan.

use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use uuid::Uuid;

/// Cryptographically secure audit chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureAuditChain {
    pub chain_id: String,
    pub content_hash: String,
    pub merkle_root: String,
    pub signature: String,
    pub timestamp: DateTime<Utc>,
    pub parent_hashes: Vec<String>,
    pub audit_data: AuditData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditData {
    pub user_id: String,
    pub action: String,
    pub resource: String,
    pub session_id: String,
    pub loa: String,
    pub metadata: HashMap<String, String>,
}

impl SecureAuditChain {
    /// Create a new cryptographically secure audit chain
    pub fn create_chain(
        audit_data: AuditData,
        parent_chains: &[SecureAuditChain],
        signing_key: &SigningKey,
    ) -> Result<Self, String> {
        let mut hasher = Sha256::new();

        // Hash the audit data
        let data_json = serde_json::to_string(&audit_data)
            .map_err(|e| format!("Failed to serialize audit data: {e}"))?;
        hasher.update(data_json.as_bytes());

        // Include parent hashes in content hash for chain integrity
        for parent in parent_chains {
            hasher.update(&parent.content_hash);
        }

        let content_hash = format!("{:x}", hasher.finalize());

        // Create Merkle tree from content and parent hashes
        let merkle_root = Self::create_merkle_root(&audit_data, parent_chains)?;

        // Sign the chain
        let signature_data = format!(
            "{}:{}:{}",
            content_hash,
            merkle_root,
            Utc::now().timestamp()
        );
        let signature = signing_key.sign(signature_data.as_bytes());

        Ok(SecureAuditChain {
            chain_id: Uuid::new_v4().to_string(),
            content_hash,
            merkle_root,
            signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
            timestamp: Utc::now(),
            parent_hashes: parent_chains
                .iter()
                .map(|c| c.content_hash.clone())
                .collect(),
            audit_data,
        })
    }

    /// Verify the integrity of this audit chain
    pub fn verify_integrity(&self, verifying_key: &VerifyingKey) -> Result<bool, String> {
        // Verify signature
        let signature_data = format!(
            "{}:{}:{}",
            self.content_hash,
            self.merkle_root,
            self.timestamp.timestamp()
        );
        let signature_bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.signature)
            .map_err(|e| format!("Invalid signature encoding: {e}"))?;
        if signature_bytes.len() != 64 {
            return Err("Invalid signature length".to_string());
        }
        let mut signature_array = [0u8; 64];
        signature_array.copy_from_slice(&signature_bytes);
        let signature = Signature::from_bytes(&signature_array);

        verifying_key
            .verify(signature_data.as_bytes(), &signature)
            .map(|_| true)
            .map_err(|e| format!("Signature verification failed: {e}"))
    }

    /// Verify the content hash matches the audit data
    pub fn verify_content_hash(&self) -> Result<bool, String> {
        let mut hasher = Sha256::new();

        // Hash the audit data
        let data_json = serde_json::to_string(&self.audit_data)
            .map_err(|e| format!("Failed to serialize audit data: {e}"))?;
        hasher.update(data_json.as_bytes());

        // Include parent hashes
        for parent_hash in &self.parent_hashes {
            hasher.update(parent_hash);
        }

        let expected_hash = format!("{:x}", hasher.finalize());
        Ok(expected_hash == self.content_hash)
    }

    /// Create Merkle root from audit data and parent chains
    fn create_merkle_root(
        audit_data: &AuditData,
        parent_chains: &[SecureAuditChain],
    ) -> Result<String, String> {
        let mut hasher = Sha256::new();

        // Hash audit data
        let data_json = serde_json::to_string(audit_data)
            .map_err(|e| format!("Failed to serialize audit data: {e}"))?;
        hasher.update(data_json.as_bytes());

        // Hash parent chain hashes
        for parent in parent_chains {
            hasher.update(&parent.content_hash);
        }

        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Get the audit chain lineage (all parent chains)
    pub fn get_lineage(&self) -> Vec<String> {
        self.parent_hashes.clone()
    }

    /// Check if this chain is a descendant of another chain
    pub fn is_descendant_of(&self, ancestor_chain_id: &str) -> bool {
        self.parent_hashes.iter().any(|hash| {
            // In a real implementation, you'd look up the chain by hash
            // and check if it's the ancestor or has the ancestor in its lineage
            hash.contains(ancestor_chain_id)
        })
    }
}

/// Immutable audit store for secure audit trail storage
pub struct ImmutableAuditStore {
    storage_path: String,
    verifying_key: VerifyingKey,
}

impl ImmutableAuditStore {
    /// Create a new immutable audit store
    pub fn new(storage_path: String, signing_key: SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        Self {
            storage_path,
            verifying_key,
        }
    }

    /// Write a secure audit chain to the immutable log
    pub fn write_chain(&self, chain: &SecureAuditChain) -> Result<(), String> {
        // Verify chain integrity before writing
        if !chain.verify_integrity(&self.verifying_key)? {
            return Err("Chain integrity verification failed".to_string());
        }

        if !chain.verify_content_hash()? {
            return Err("Content hash verification failed".to_string());
        }

        // Append to immutable log
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.storage_path)
            .map_err(|e| format!("Failed to open audit log: {e}"))?;

        let json =
            serde_json::to_string(chain).map_err(|e| format!("Failed to serialize chain: {e}"))?;

        writeln!(file, "{json}").map_err(|e| format!("Failed to write chain: {e}"))?;

        Ok(())
    }

    /// Read all audit chains from the store
    pub fn read_all_chains(&self) -> Result<Vec<SecureAuditChain>, String> {
        let file =
            File::open(&self.storage_path).map_err(|e| format!("Failed to open audit log: {e}"))?;

        let reader = BufReader::new(file);
        let mut chains = Vec::new();

        for line in reader.lines() {
            let line = line.map_err(|e| format!("Failed to read line: {e}"))?;
            if line.trim().is_empty() {
                continue;
            }

            let chain: SecureAuditChain =
                serde_json::from_str(&line).map_err(|e| format!("Failed to parse chain: {e}"))?;

            // Verify integrity of each chain
            if !chain.verify_integrity(&self.verifying_key)? {
                return Err(format!(
                    "Chain {} integrity verification failed",
                    chain.chain_id
                ));
            }

            chains.push(chain);
        }

        Ok(chains)
    }

    /// Verify the integrity of the entire audit log
    pub fn verify_log_integrity(&self) -> Result<bool, String> {
        let chains = self.read_all_chains()?;

        for chain in chains {
            if !chain.verify_integrity(&self.verifying_key)? {
                return Ok(false);
            }
            if !chain.verify_content_hash()? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Get audit statistics
    pub fn get_audit_stats(&self) -> Result<AuditStats, String> {
        let chains = self.read_all_chains()?;

        let mut user_actions = HashMap::new();
        let mut resource_access = HashMap::new();
        let mut loa_distribution = HashMap::new();

        for chain in &chains {
            // Count user actions
            *user_actions
                .entry(chain.audit_data.user_id.clone())
                .or_insert(0) += 1;

            // Count resource access
            *resource_access
                .entry(chain.audit_data.resource.clone())
                .or_insert(0) += 1;

            // Count LOA distribution
            *loa_distribution
                .entry(chain.audit_data.loa.clone())
                .or_insert(0) += 1;
        }

        Ok(AuditStats {
            total_chains: chains.len(),
            user_actions,
            resource_access,
            loa_distribution,
            first_chain_time: chains.first().map(|c| c.timestamp),
            last_chain_time: chains.last().map(|c| c.timestamp),
        })
    }
}

/// Audit statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStats {
    pub total_chains: usize,
    pub user_actions: HashMap<String, usize>,
    pub resource_access: HashMap<String, usize>,
    pub loa_distribution: HashMap<String, usize>,
    pub first_chain_time: Option<DateTime<Utc>>,
    pub last_chain_time: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_secure_audit_chain_creation() {
        let signing_key = SigningKey::generate(&mut OsRng);

        let audit_data = AuditData {
            user_id: "test_user".to_string(),
            action: "read".to_string(),
            resource: "canon".to_string(),
            session_id: "session_123".to_string(),
            loa: "Observer".to_string(),
            metadata: HashMap::new(),
        };

        let chain = SecureAuditChain::create_chain(audit_data, &[], &signing_key).unwrap();

        assert!(!chain.chain_id.is_empty());
        assert!(!chain.content_hash.is_empty());
        assert!(!chain.signature.is_empty());
        assert!(chain.parent_hashes.is_empty());
    }

    #[test]
    fn test_secure_audit_chain_integrity() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let audit_data = AuditData {
            user_id: "test_user".to_string(),
            action: "write".to_string(),
            resource: "canon".to_string(),
            session_id: "session_456".to_string(),
            loa: "Operator".to_string(),
            metadata: HashMap::new(),
        };

        let chain = SecureAuditChain::create_chain(audit_data, &[], &signing_key).unwrap();

        // Verify integrity
        assert!(chain.verify_integrity(&verifying_key).unwrap());
        assert!(chain.verify_content_hash().unwrap());
    }

    #[test]
    fn test_audit_chain_lineage() {
        let signing_key = SigningKey::generate(&mut OsRng);

        // Create parent chain
        let parent_data = AuditData {
            user_id: "parent_user".to_string(),
            action: "create".to_string(),
            resource: "canon".to_string(),
            session_id: "session_parent".to_string(),
            loa: "Root".to_string(),
            metadata: HashMap::new(),
        };

        let parent_chain = SecureAuditChain::create_chain(parent_data, &[], &signing_key).unwrap();

        // Create child chain
        let child_data = AuditData {
            user_id: "child_user".to_string(),
            action: "modify".to_string(),
            resource: "canon".to_string(),
            session_id: "session_child".to_string(),
            loa: "Operator".to_string(),
            metadata: HashMap::new(),
        };

        let child_chain =
            SecureAuditChain::create_chain(child_data, std::slice::from_ref(&parent_chain), &signing_key)
                .unwrap();

        // Verify lineage
        assert_eq!(child_chain.parent_hashes.len(), 1);
        assert_eq!(child_chain.parent_hashes[0], parent_chain.content_hash);
    }
}
