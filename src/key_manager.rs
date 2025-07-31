use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use crate::errors::SigilResult;
use base64::Engine;

/// Represents a cryptographic key pair for Sigil license signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigilKeyPair {
    pub key_id: String,
    pub public_key: String,
    pub private_key: String, // Base64 encoded, should be stored securely
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub key_type: KeyType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyType {
    LicenseSigning,
    CanonSealing,
    WitnessSigning,
}

impl SigilKeyPair {
    /// Generate a new Ed25519 key pair
    pub fn generate(key_id: &str, key_type: KeyType) -> SigilResult<Self> {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        
        let public_key = base64::engine::general_purpose::STANDARD.encode(verifying_key.to_bytes());
        let private_key = base64::engine::general_purpose::STANDARD.encode(signing_key.to_bytes());
        
        Ok(SigilKeyPair {
            key_id: key_id.to_string(),
            public_key,
            private_key,
            created_at: chrono::Utc::now(),
            key_type,
        })
    }
    
    /// Sign data with the private key
    pub fn sign(&self, data: &[u8]) -> SigilResult<String> {
        let private_key_bytes = base64::engine::general_purpose::STANDARD.decode(&self.private_key)
            .map_err(|e| crate::errors::SigilError::auth(format!("Failed to decode private key: {}", e)))?;
        
        if private_key_bytes.len() != 32 {
            return Err(crate::errors::SigilError::auth("Invalid private key length".to_string()));
        }
        
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&private_key_bytes);
        
        let signing_key = SigningKey::from_bytes(&key_array);
        let signature = signing_key.sign(data);
        
        Ok(base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()))
    }
    
    /// Verify a signature with the public key
    pub fn verify(&self, data: &[u8], signature: &str) -> SigilResult<bool> {
        let public_key_bytes = base64::engine::general_purpose::STANDARD.decode(&self.public_key)
            .map_err(|e| crate::errors::SigilError::auth(format!("Failed to decode public key: {}", e)))?;
        
        let signature_bytes = base64::engine::general_purpose::STANDARD.decode(signature)
            .map_err(|e| crate::errors::SigilError::auth(format!("Failed to decode signature: {}", e)))?;
        
        if public_key_bytes.len() != 32 {
            return Err(crate::errors::SigilError::auth("Invalid public key length".to_string()));
        }
        
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&public_key_bytes);
        
        let verifying_key = VerifyingKey::from_bytes(&key_array)
            .map_err(|e| crate::errors::SigilError::auth(format!("Invalid public key: {}", e)))?;
        
        let signature = Signature::try_from(&signature_bytes[..])
            .map_err(|e| crate::errors::SigilError::auth(format!("Invalid signature: {}", e)))?;
        
        Ok(verifying_key.verify(data, &signature).is_ok())
    }
    
    /// Save the key pair to a file (private key should be encrypted in production)
    pub fn save_to_file(&self, path: &str) -> SigilResult<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| crate::errors::SigilError::serialization("Failed to serialize key pair".to_string(), e))?;
        
        fs::write(path, json)
            .map_err(|e| crate::errors::SigilError::auth(format!("Failed to write key file: {}", e)))?;
        
        Ok(())
    }
    
    /// Load a key pair from a file
    pub fn load_from_file(path: &str) -> SigilResult<Self> {
        let content = fs::read_to_string(path)
            .map_err(|e| crate::errors::SigilError::auth(format!("Failed to read key file: {}", e)))?;
        
        let key_pair: SigilKeyPair = serde_json::from_str(&content)
            .map_err(|e| crate::errors::SigilError::serialization("Failed to parse key file".to_string(), e))?;
        
        Ok(key_pair)
    }
}

/// Key manager for handling multiple key pairs
pub struct KeyManager {
    keys: std::collections::HashMap<String, SigilKeyPair>,
}

impl KeyManager {
    pub fn new() -> Self {
        KeyManager {
            keys: std::collections::HashMap::new(),
        }
    }
    
    /// Generate and store a new key pair
    pub fn generate_key(&mut self, key_id: &str, key_type: KeyType) -> SigilResult<&SigilKeyPair> {
        let key_pair = SigilKeyPair::generate(key_id, key_type)?;
        self.keys.insert(key_id.to_string(), key_pair);
        Ok(self.keys.get(key_id).unwrap())
    }
    
    /// Get a key pair by ID
    pub fn get_key(&self, key_id: &str) -> Option<&SigilKeyPair> {
        self.keys.get(key_id)
    }
    
    /// Sign data with a specific key
    pub fn sign_with_key(&self, key_id: &str, data: &[u8]) -> SigilResult<String> {
        let key_pair = self.keys.get(key_id)
            .ok_or_else(|| crate::errors::SigilError::auth(format!("Key not found: {}", key_id)))?;
        
        key_pair.sign(data)
    }
    
    /// Verify a signature with a specific key
    pub fn verify_with_key(&self, key_id: &str, data: &[u8], signature: &str) -> SigilResult<bool> {
        let key_pair = self.keys.get(key_id)
            .ok_or_else(|| crate::errors::SigilError::auth(format!("Key not found: {}", key_id)))?;
        
        key_pair.verify(data, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_key_generation() {
        let key_pair = SigilKeyPair::generate("test_key", KeyType::LicenseSigning).unwrap();
        assert_eq!(key_pair.key_id, "test_key");
        assert!(!key_pair.public_key.is_empty());
        assert!(!key_pair.private_key.is_empty());
    }
    
    #[test]
    fn test_sign_and_verify() {
        let key_pair = SigilKeyPair::generate("test_key", KeyType::LicenseSigning).unwrap();
        let data = b"Hello, Sigil!";
        
        let signature = key_pair.sign(data).unwrap();
        let is_valid = key_pair.verify(data, &signature).unwrap();
        
        assert!(is_valid);
    }
    
    #[test]
    fn test_key_manager() {
        let mut manager = KeyManager::new();
        let key_pair = manager.generate_key("test_key", KeyType::LicenseSigning).unwrap();
        
        let data = b"Test data";
        let signature = manager.sign_with_key("test_key", data).unwrap();
        let is_valid = manager.verify_with_key("test_key", data, &signature).unwrap();
        
        assert!(is_valid);
    }
} 