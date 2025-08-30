//! Witness Registry
//! 
//! This module manages trusted witness public keys for the quorum system.
//! Witnesses are stored in Canon system space and can be added/removed/listed.

use crate::canon_store::CanonStore;
use crate::canonical_record::CanonicalRecord;
use crate::loa::LOA;
use crate::errors::{SigilResult, SigilError};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use base64::Engine;

/// A trusted witness in the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedWitness {
    pub witness_id: String,
    pub public_key: String, // Base64 encoded Ed25519 public key
    pub authority: String,  // Who authorized this witness
    pub added_at: DateTime<Utc>,
    pub description: String,
    pub is_active: bool,
}

impl TrustedWitness {
    pub fn new(
        witness_id: String,
        public_key: String,
        authority: String,
        description: String,
    ) -> Self {
        Self {
            witness_id,
            public_key,
            authority,
            added_at: Utc::now(),
            description,
            is_active: true,
        }
    }
}

/// Registry for managing trusted witnesses
pub struct WitnessRegistry {
    canon_store: Arc<Mutex<dyn CanonStore>>,
    cache: std::sync::RwLock<HashMap<String, TrustedWitness>>,
}

impl WitnessRegistry {
    pub fn new(canon_store: Arc<Mutex<dyn CanonStore>>) -> SigilResult<Self> {
        let registry = Self {
            canon_store,
            cache: std::sync::RwLock::new(HashMap::new()),
        };
        
        // Load existing witnesses from Canon
        registry.reload_from_canon()?;
        
        Ok(registry)
    }
    
    /// Add a new trusted witness
    pub fn add_witness(
        &self,
        witness_id: String,
        public_key: String,
        authority: String,
        description: String,
        requester_loa: &LOA,
    ) -> SigilResult<()> {
        // Only Root can add witnesses
        if !matches!(requester_loa, LOA::Root) {
            return Err(SigilError::insufficient_loa(
                LOA::Root,
                requester_loa.clone(),
            ));
        }
        
        // Validate the witness_id doesn't already exist
        {
            let cache = self.cache.read().map_err(|_| SigilError::internal("cache lock poisoned"))?;
            if cache.contains_key(&witness_id) {
                return Err(SigilError::invalid_input(
                    "add_witness",
                    &format!("Witness {} already exists", witness_id),
                ));
            }
        }
        
        // Validate public key format (basic check for base64)
        if let Err(_) = base64::engine::general_purpose::STANDARD.decode(&public_key) {
            return Err(SigilError::invalid_input(
                "add_witness",
                "Invalid base64 public key",
            ));
        }
        
        let witness = TrustedWitness::new(witness_id.clone(), public_key, authority, description);
        
        // Store in Canon
        self.store_witness_in_canon(&witness)?;
        
        // Update cache
        {
            let mut cache = self.cache.write().map_err(|_| SigilError::internal("cache lock poisoned"))?;
            cache.insert(witness_id, witness);
        }
        
        Ok(())
    }
    
    /// Remove a trusted witness (mark as inactive)
    pub fn remove_witness(&self, witness_id: &str, requester_loa: &LOA) -> SigilResult<()> {
        // Only Root can remove witnesses
        if !matches!(requester_loa, LOA::Root) {
            return Err(SigilError::insufficient_loa(
                LOA::Root,
                requester_loa.clone(),
            ));
        }
        
        // Get the witness and mark as inactive
        let mut witness = {
            let cache = self.cache.read().map_err(|_| SigilError::internal("cache lock poisoned"))?;
            cache.get(witness_id)
                .ok_or_else(|| SigilError::not_found("witness", witness_id))?
                .clone()
        };
        
        witness.is_active = false;
        
        // Store updated witness in Canon
        self.store_witness_in_canon(&witness)?;
        
        // Update cache
        {
            let mut cache = self.cache.write().map_err(|_| SigilError::internal("cache lock poisoned"))?;
            cache.insert(witness_id.to_string(), witness);
        }
        
        Ok(())
    }
    
    /// Get a trusted witness by ID
    pub fn get_witness(&self, witness_id: &str) -> Option<TrustedWitness> {
        self.cache.read().ok()?.get(witness_id).cloned()
    }
    
    /// List all active trusted witnesses
    pub fn list_active_witnesses(&self) -> Vec<TrustedWitness> {
        self.cache.read()
            .map(|cache| cache.values()
                .filter(|w| w.is_active)
                .cloned()
                .collect())
            .unwrap_or_default()
    }
    
    /// Check if a witness is trusted and active
    pub fn is_trusted_witness(&self, witness_id: &str) -> bool {
        self.cache.read()
            .map(|cache| cache.get(witness_id)
                .map(|w| w.is_active)
                .unwrap_or(false))
            .unwrap_or(false)
    }
    
    /// Validate a witness signature (stub for now - would need crypto validation)
    pub fn validate_witness_signature(
        &self,
        witness_id: &str,
        _message: &[u8], // TODO: Use in actual Ed25519 verification
        signature: &str,
    ) -> SigilResult<bool> {
        let witness = self.get_witness(witness_id)
            .ok_or_else(|| SigilError::not_found("witness", witness_id))?;
        
        if !witness.is_active {
            return Ok(false);
        }
        
        // TODO: Implement actual Ed25519 signature validation
        // For now, return true if the witness exists and is active
        // In a real implementation, this would:
        // 1. Decode the base64 public key
        // 2. Decode the base64 signature  
        // 3. Verify the signature against the message using Ed25519
        
        if signature.is_empty() {
            return Ok(false);
        }
        
        Ok(true) // Stub implementation
    }
    
    /// Reload witness registry from Canon
    pub fn reload_from_canon(&self) -> SigilResult<()> {
        let canon_store = self.canon_store.lock()
            .map_err(|_| SigilError::internal("canon store lock poisoned"))?;
        
        let records = canon_store.list_records(Some("trusted_witness"), &LOA::Root);
        
        let mut cache = self.cache.write()
            .map_err(|_| SigilError::internal("cache lock poisoned"))?;
        cache.clear();
        
        for record in records {
            match serde_json::from_value::<TrustedWitness>(record.payload) {
                Ok(witness) => {
                    cache.insert(witness.witness_id.clone(), witness);
                }
                Err(e) => {
                    log::warn!("Failed to deserialize witness from record {}: {}", record.id, e);
                }
            }
        }
        
        log::info!("Loaded {} witnesses from Canon", cache.len());
        Ok(())
    }
    
    /// Store a witness in Canon as a CanonicalRecord
    fn store_witness_in_canon(&self, witness: &TrustedWitness) -> SigilResult<()> {
        let payload = serde_json::to_value(witness)
            .map_err(|e| SigilError::internal(&format!("Failed to serialize witness: {}", e)))?;
        
        let record = CanonicalRecord {
            kind: "trusted_witness".to_string(),
            schema_version: 1,
            id: format!("witness:{}", witness.witness_id),
            tenant: "system".to_string(),
            ts: Utc::now(),
            space: "system".to_string(),
            payload,
            links: vec![],
            prev: None,
            hash: String::new(), // Will be computed by canonicalizer
            sig: None,           // System records don't need signatures yet
            pub_key: None,
            witnesses: vec![],
        };
        
        let mut canon_store = self.canon_store.lock()
            .map_err(|_| SigilError::internal("canon store lock poisoned"))?;
        
        canon_store.add_record(record, &LOA::Root, true)
            .map_err(|e| SigilError::internal(&format!("Failed to store witness: {}", e)))?;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canon_store_sled::CanonStoreSled;
    use tempfile::TempDir;
    
    fn create_test_registry() -> (WitnessRegistry, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let canon_store = Arc::new(Mutex::new(
            CanonStoreSled::new(temp_dir.path().to_str().unwrap()).unwrap()
        ));
        let registry = WitnessRegistry::new(canon_store).unwrap();
        (registry, temp_dir)
    }
    
    #[test]
    fn test_add_witness() {
        let (registry, _temp_dir) = create_test_registry();
        
        let result = registry.add_witness(
            "witness1".to_string(),
            "dGVzdF9wdWJsaWNfa2V5".to_string(), // "test_public_key" in base64
            "test_authority".to_string(),
            "Test witness".to_string(),
            &LOA::Root,
        );
        
        assert!(result.is_ok());
        assert!(registry.is_trusted_witness("witness1"));
    }
    
    #[test]
    fn test_insufficient_loa() {
        let (registry, _temp_dir) = create_test_registry();
        
        let result = registry.add_witness(
            "witness1".to_string(),
            "dGVzdF9wdWJsaWNfa2V5".to_string(),
            "test_authority".to_string(),
            "Test witness".to_string(),
            &LOA::Operator, // Not Root
        );
        
        assert!(result.is_err());
    }
    
    #[test]
    fn test_remove_witness() {
        let (registry, _temp_dir) = create_test_registry();
        
        // Add a witness first
        registry.add_witness(
            "witness1".to_string(),
            "dGVzdF9wdWJsaWNfa2V5".to_string(),
            "test_authority".to_string(),
            "Test witness".to_string(),
            &LOA::Root,
        ).unwrap();
        
        assert!(registry.is_trusted_witness("witness1"));
        
        // Remove the witness
        registry.remove_witness("witness1", &LOA::Root).unwrap();
        
        assert!(!registry.is_trusted_witness("witness1"));
    }
    
    #[test]
    fn test_list_active_witnesses() {
        let (registry, _temp_dir) = create_test_registry();
        
        // Add two witnesses
        registry.add_witness(
            "witness1".to_string(),
            "dGVzdF9wdWJsaWNfa2V5MQ==".to_string(),
            "test_authority".to_string(),
            "Test witness 1".to_string(),
            &LOA::Root,
        ).unwrap();
        
        registry.add_witness(
            "witness2".to_string(),
            "dGVzdF9wdWJsaWNfa2V5Mg==".to_string(),
            "test_authority".to_string(),
            "Test witness 2".to_string(),
            &LOA::Root,
        ).unwrap();
        
        let active_witnesses = registry.list_active_witnesses();
        assert_eq!(active_witnesses.len(), 2);
        
        // Remove one witness
        registry.remove_witness("witness1", &LOA::Root).unwrap();
        
        let active_witnesses = registry.list_active_witnesses();
        assert_eq!(active_witnesses.len(), 1);
        assert_eq!(active_witnesses[0].witness_id, "witness2");
    }
}
