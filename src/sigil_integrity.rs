use crate::loa::LoaLevel;
use serde::{Deserialize, Serialize};
use ed25519_dalek::{VerifyingKey, Signature, Verifier, Signer};
use std::collections::HashMap;
use std::sync::Mutex;
use lazy_static::lazy_static;
use crate::errors::SigilResult;
use base64::Engine;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessSignature {
    pub witness_id: String,
    pub signature: String,
}

lazy_static! {
    static ref WITNESS_REGISTRY: Mutex<HashMap<String, VerifyingKey>> = Mutex::new(HashMap::new());
}

/// Load a witness public key from file
fn load_witness_key(path: &str) -> Result<VerifyingKey, String> {
    let key_bytes = std::fs::read(path)
        .map_err(|e| format!("Failed to load witness key from {path}: {e}"))?;
    
    if key_bytes.len() != 32 {
        return Err(format!("Invalid key length: expected 32 bytes, got {}", key_bytes.len()));
    }
    
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key_bytes);
    
    VerifyingKey::from_bytes(&key_array)
        .map_err(|e| format!("Invalid witness key format in {path}: {e}"))
}

/// Initialize the witness registry with trusted public keys
pub fn initialize_witness_registry() -> SigilResult<()> {
    let mut registry = WITNESS_REGISTRY.lock()
        .map_err(|_| crate::errors::SigilError::internal("Failed to acquire witness registry lock"))?;
    
    // Load trusted witness public keys
    let witness_keys = [
        ("sigil_init_loader", "keys/witnesses/init_loader.pub"),
        ("root_mnemonic", "keys/witnesses/root_mnemonic.pub"),
        ("first_trust_agent", "keys/witnesses/trust_agent.pub"),
        ("canon_validator", "keys/witnesses/canon_validator.pub"),
        ("audit_chain", "keys/witnesses/audit_chain.pub"),
    ];
    
    for (witness_id, key_path) in witness_keys.iter() {
        match load_witness_key(key_path) {
            Ok(public_key) => {
                registry.insert(witness_id.to_string(), public_key);
                log::info!("Loaded witness key for: {witness_id}");
            }
            Err(e) => {
                log::warn!("Failed to load witness key for {witness_id}: {e}");
            }
        }
    }
    
    Ok(())
}

/// Add a new witness to the registry
pub fn add_witness(witness_id: &str, public_key: VerifyingKey) -> SigilResult<()> {
    let mut registry = WITNESS_REGISTRY.lock()
        .map_err(|_| crate::errors::SigilError::internal("Failed to acquire witness registry lock"))?;
    
    registry.insert(witness_id.to_string(), public_key);
    log::info!("Added witness to registry: {witness_id}");
    
    Ok(())
}

/// Remove a witness from the registry
pub fn remove_witness(witness_id: &str) -> SigilResult<()> {
    let mut registry = WITNESS_REGISTRY.lock()
        .map_err(|_| crate::errors::SigilError::internal("Failed to acquire witness registry lock"))?;
    
    if registry.remove(witness_id).is_some() {
        log::info!("Removed witness from registry: {witness_id}");
    } else {
        log::warn!("Witness not found in registry: {witness_id}");
    }
    
    Ok(())
}

/// Get the number of registered witnesses
pub fn get_witness_count() -> SigilResult<usize> {
    let registry = WITNESS_REGISTRY.lock()
        .map_err(|_| crate::errors::SigilError::internal("Failed to acquire witness registry lock"))?;
    
    Ok(registry.len())
}

/// Validate witness signatures cryptographically
pub fn validate_witnesses(
    witnesses: &[WitnessSignature],
    _required_loa: &LoaLevel,
    payload: &str,
) -> SigilResult<bool> {
    // Check minimum witness count
    if witnesses.len() < 3 {
        log::warn!("Witness quorum not satisfied: {} witnesses, minimum 3 required", witnesses.len());
        return Ok(false);
    }
    
    // Check maximum witness count to prevent abuse
    if witnesses.len() > 10 {
        log::warn!("Too many witnesses: {} witnesses, maximum 10 allowed", witnesses.len());
        return Ok(false);
    }
    
    let registry = WITNESS_REGISTRY.lock()
        .map_err(|_| crate::errors::SigilError::internal("Failed to acquire witness registry lock"))?;
    
    if registry.is_empty() {
        log::error!("Witness registry is empty - cannot validate signatures");
        return Ok(false);
    }
    
    let mut valid_signatures = 0;
    let mut verified_witnesses = Vec::new();
    
    for witness in witnesses {
        // Check for duplicate witnesses
        if verified_witnesses.contains(&witness.witness_id) {
            log::warn!("Duplicate witness signature from: {}", witness.witness_id);
            continue;
        }
        
        if let Some(public_key) = registry.get(&witness.witness_id) {
            // Decode base64 signature
            let signature_bytes = match base64::engine::general_purpose::STANDARD.decode(&witness.signature) {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::warn!("Invalid signature encoding for witness {}: {}", witness.witness_id, e);
                    continue;
                }
            };
            
            // Parse signature
            let signature = match Signature::try_from(signature_bytes.as_slice()) {
                Ok(sig) => sig,
                Err(e) => {
                    log::warn!("Invalid signature format for witness {}: {}", witness.witness_id, e);
                    continue;
                }
            };
            
            // Verify signature
            if public_key.verify(payload.as_bytes(), &signature).is_ok() {
                valid_signatures += 1;
                verified_witnesses.push(witness.witness_id.clone());
                log::debug!("Valid signature from witness: {}", witness.witness_id);
            } else {
                log::warn!("Invalid signature from witness: {}", witness.witness_id);
            }
        } else {
            log::warn!("Unknown witness: {}", witness.witness_id);
        }
    }
    
    // Require at least 3 valid signatures
    let is_valid = valid_signatures >= 3;
    
    if is_valid {
        log::info!("Witness validation successful: {}/{} valid signatures", valid_signatures, witnesses.len());
    } else {
        log::warn!("Witness validation failed: {}/{} valid signatures, minimum 3 required", valid_signatures, witnesses.len());
    }
    
    Ok(is_valid)
}

/// Create a witness signature (for testing and internal use)
pub fn create_witness_signature(
    witness_id: &str,
    payload: &str,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<WitnessSignature, String> {
    let signature = signing_key.sign(payload.as_bytes());
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
    
    Ok(WitnessSignature {
        witness_id: witness_id.to_string(),
        signature: signature_b64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    // OsRng is used in the test below
    
    #[test]
    fn test_witness_validation() {
        // Initialize registry with test keys
        let mut rng = rand::rngs::OsRng;
        let signing_key1 = SigningKey::generate(&mut rng);
        let signing_key2 = SigningKey::generate(&mut rng);
        let signing_key3 = SigningKey::generate(&mut rng);
        
        let verifying_key1 = signing_key1.verifying_key();
        let verifying_key2 = signing_key2.verifying_key();
        let verifying_key3 = signing_key3.verifying_key();
        
        // Add witnesses to registry
        add_witness("test_witness_1", verifying_key1).unwrap();
        add_witness("test_witness_2", verifying_key2).unwrap();
        add_witness("test_witness_3", verifying_key3).unwrap();
        
        let payload = "test_payload_for_signature_verification";
        
        // Create valid signatures
        let sig1 = create_witness_signature("test_witness_1", payload, &signing_key1).unwrap();
        let sig2 = create_witness_signature("test_witness_2", payload, &signing_key2).unwrap();
        let sig3 = create_witness_signature("test_witness_3", payload, &signing_key3).unwrap();
        
        let witnesses = vec![sig1, sig2, sig3];
        
        // Test valid witness validation
        let result = validate_witnesses(&witnesses, &LoaLevel::Root, payload).unwrap();
        assert!(result, "Witness validation should succeed with 3 valid signatures");
    }
    
    #[test]
    fn test_insufficient_witnesses() {
        let payload = "test_payload";
        let witnesses = vec![
            WitnessSignature {
                witness_id: "witness1".to_string(),
                signature: "invalid_signature".to_string(),
            },
            WitnessSignature {
                witness_id: "witness2".to_string(),
                signature: "invalid_signature".to_string(),
            },
        ];
        
        let result = validate_witnesses(&witnesses, &LoaLevel::Root, payload).unwrap();
        assert!(!result, "Witness validation should fail with less than 3 witnesses");
    }
}
