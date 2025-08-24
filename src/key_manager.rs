use crate::errors::SigilResult;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use rand::RngCore;

/// Represents a cryptographic key pair for Sigil license signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigilKeyPair {
    pub key_id: String,
    pub public_key: String,
    pub private_key: String, // Base64 encoded, should be stored securely
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub key_type: KeyType,
}

/// Secure key pair with encrypted private key storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureKeyPair {
    pub key_id: String,
    pub public_key: String,
    encrypted_private_key: Vec<u8>,
    pub key_type: KeyType,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyType {
    LicenseSigning,
    CanonSealing,
    WitnessSigning,
}

impl SecureKeyPair {
    /// Generate a new Ed25519 key pair with encrypted private key storage
    pub fn generate(key_id: &str, key_type: KeyType, master_key: &[u8; 32]) -> SigilResult<Self> {
        let mut key_bytes = [0u8; 32];
        getrandom::fill(&mut key_bytes)
            .map_err(|e| crate::errors::SigilError::auth(format!("Failed to generate key: {e}")))?;
        
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let verifying_key = signing_key.verifying_key();

        let public_key = base64::engine::general_purpose::STANDARD.encode(verifying_key.to_bytes());
        
        // Encrypt private key with master key
        let cipher = Aes256Gcm::new_from_slice(master_key)
            .map_err(|e| crate::errors::SigilError::encryption(format!("Invalid master key: {e}")))?;
        
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let encrypted_private = cipher.encrypt(&nonce.into(), key_bytes.as_ref())
            .map_err(|e| crate::errors::SigilError::encryption(format!("Failed to encrypt private key: {e}")))?;
        
        let mut encrypted_data = nonce.to_vec();
        encrypted_data.extend_from_slice(&encrypted_private);

        Ok(SecureKeyPair {
            key_id: key_id.to_string(),
            public_key,
            encrypted_private_key: encrypted_data,
            key_type,
            created_at: chrono::Utc::now(),
        })
    }

    /// Sign data with the private key (requires master key for decryption)
    pub fn sign(&self, data: &[u8], master_key: &[u8; 32]) -> SigilResult<String> {
        let cipher = Aes256Gcm::new_from_slice(master_key)
            .map_err(|e| crate::errors::SigilError::encryption(format!("Invalid master key: {e}")))?;
        
        if self.encrypted_private_key.len() < 12 {
            return Err(crate::errors::SigilError::encryption("Invalid encrypted private key format".to_string()));
        }
        
        let nonce = &self.encrypted_private_key[..12];
        let encrypted_key = &self.encrypted_private_key[12..];
        
        let private_key_bytes = cipher.decrypt(nonce.into(), encrypted_key)
            .map_err(|e| crate::errors::SigilError::encryption(format!("Failed to decrypt private key: {e}")))?;
        
        if private_key_bytes.len() != 32 {
            return Err(crate::errors::SigilError::encryption("Invalid private key length".to_string()));
        }
        
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&private_key_bytes);

        let signing_key = SigningKey::from_bytes(&key_array);
        let signature = signing_key.sign(data);

        Ok(base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()))
    }

    /// Verify a signature with the public key
    pub fn verify(&self, data: &[u8], signature: &str) -> SigilResult<bool> {
        let public_key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.public_key)
            .map_err(|e| {
                crate::errors::SigilError::auth(format!("Failed to decode public key: {e}"))
            })?;

        let signature_bytes = base64::engine::general_purpose::STANDARD
            .decode(signature)
            .map_err(|e| {
                crate::errors::SigilError::auth(format!("Failed to decode signature: {e}"))
            })?;

        if public_key_bytes.len() != 32 {
            return Err(crate::errors::SigilError::auth(
                "Invalid public key length".to_string(),
            ));
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&public_key_bytes);

        let verifying_key = VerifyingKey::from_bytes(&key_array)
            .map_err(|e| crate::errors::SigilError::auth(format!("Invalid public key: {e}")))?;

        let signature = Signature::try_from(&signature_bytes[..])
            .map_err(|e| crate::errors::SigilError::auth(format!("Invalid signature: {e}")))?;

        Ok(verifying_key.verify(data, &signature).is_ok())
    }

    /// Save the secure key pair to a file
    pub fn save_to_file(&self, path: &str) -> SigilResult<()> {
        let json = serde_json::to_string_pretty(self).map_err(|e| {
            crate::errors::SigilError::serialization("Failed to serialize secure key pair".to_string(), e)
        })?;

        fs::write(path, json).map_err(|e| {
            crate::errors::SigilError::auth(format!("Failed to write key file: {e}"))
        })?;

        Ok(())
    }

    /// Load a secure key pair from a file
    pub fn load_from_file(path: &str) -> SigilResult<Self> {
        let content = fs::read_to_string(path).map_err(|e| {
            crate::errors::SigilError::auth(format!("Failed to read key file: {e}"))
        })?;

        let key_pair: SecureKeyPair = serde_json::from_str(&content).map_err(|e| {
            crate::errors::SigilError::serialization("Failed to parse key file".to_string(), e)
        })?;

        Ok(key_pair)
    }
}

/// Derive master key from password using Argon2
pub fn derive_master_key(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    use argon2::{Argon2, PasswordHasher};
    use argon2::password_hash::SaltString;
    
    let argon2 = Argon2::default();
    let salt_string = SaltString::encode_b64(salt)
        .map_err(|e| format!("Failed to encode salt: {e}"))?;
    
    let password_hash = argon2.hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| format!("Failed to hash password: {e}"))?;
    
    let hash = password_hash.hash
        .ok_or("Password hash is empty")?;
    let hash_bytes = hash.as_bytes();
    
    if hash_bytes.len() < 32 {
        return Err("Generated hash is too short".to_string());
    }
    
    let mut master_key = [0u8; 32];
    master_key.copy_from_slice(&hash_bytes[..32]);
    
    Ok(master_key)
}

/// Generate a secure salt for key derivation
pub fn generate_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

// Legacy implementation for backward compatibility
impl SigilKeyPair {
    /// Generate a new Ed25519 key pair
    pub fn generate(key_id: &str, key_type: KeyType) -> SigilResult<Self> {
        let mut key_bytes = [0u8; 32];
        getrandom::fill(&mut key_bytes)
            .map_err(|e| crate::errors::SigilError::auth(format!("Failed to generate key: {e}")))?;
        let signing_key = SigningKey::from_bytes(&key_bytes);
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
        let private_key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.private_key)
            .map_err(|e| {
                crate::errors::SigilError::auth(format!("Failed to decode private key: {e}"))
            })?;

        if private_key_bytes.len() != 32 {
            return Err(crate::errors::SigilError::auth(
                "Invalid private key length".to_string(),
            ));
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&private_key_bytes);

        let signing_key = SigningKey::from_bytes(&key_array);
        let signature = signing_key.sign(data);

        Ok(base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()))
    }

    /// Verify a signature with the public key
    pub fn verify(&self, data: &[u8], signature: &str) -> SigilResult<bool> {
        let public_key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.public_key)
            .map_err(|e| {
                crate::errors::SigilError::auth(format!("Failed to decode public key: {e}"))
            })?;

        let signature_bytes = base64::engine::general_purpose::STANDARD
            .decode(signature)
            .map_err(|e| {
                crate::errors::SigilError::auth(format!("Failed to decode signature: {e}"))
            })?;

        if public_key_bytes.len() != 32 {
            return Err(crate::errors::SigilError::auth(
                "Invalid public key length".to_string(),
            ));
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&public_key_bytes);

        let verifying_key = VerifyingKey::from_bytes(&key_array)
            .map_err(|e| crate::errors::SigilError::auth(format!("Invalid public key: {e}")))?;

        let signature = Signature::try_from(&signature_bytes[..])
            .map_err(|e| crate::errors::SigilError::auth(format!("Invalid signature: {e}")))?;

        Ok(verifying_key.verify(data, &signature).is_ok())
    }

    /// Save the key pair to a file (private key should be encrypted in production)
    pub fn save_to_file(&self, path: &str) -> SigilResult<()> {
        let json = serde_json::to_string_pretty(self).map_err(|e| {
            crate::errors::SigilError::serialization("Failed to serialize key pair".to_string(), e)
        })?;

        fs::write(path, json).map_err(|e| {
            crate::errors::SigilError::auth(format!("Failed to write key file: {e}"))
        })?;

        Ok(())
    }

    /// Load a key pair from a file
    pub fn load_from_file(path: &str) -> SigilResult<Self> {
        let content = fs::read_to_string(path).map_err(|e| {
            crate::errors::SigilError::auth(format!("Failed to read key file: {e}"))
        })?;

        let key_pair: SigilKeyPair = serde_json::from_str(&content).map_err(|e| {
            crate::errors::SigilError::serialization("Failed to parse key file".to_string(), e)
        })?;

        Ok(key_pair)
    }
}

/// Key manager for handling multiple key pairs
pub struct KeyManager {
    keys: std::collections::HashMap<String, SigilKeyPair>,
    secure_keys: std::collections::HashMap<String, SecureKeyPair>,
    master_key: Option<[u8; 32]>,
}

impl KeyManager {
    pub fn new() -> Self {
        KeyManager {
            keys: std::collections::HashMap::new(),
            secure_keys: std::collections::HashMap::new(),
            master_key: None,
        }
    }

    /// Set the master key for secure key operations
    pub fn set_master_key(&mut self, master_key: [u8; 32]) {
        self.master_key = Some(master_key);
    }

    /// Generate and store a new secure key pair
    pub fn generate_secure_key(&mut self, key_id: &str, key_type: KeyType) -> SigilResult<&SecureKeyPair> {
        let master_key = self.master_key
            .ok_or_else(|| crate::errors::SigilError::auth("Master key not set".to_string()))?;
        
        let key_pair = SecureKeyPair::generate(key_id, key_type, &master_key)?;
        self.secure_keys.insert(key_id.to_string(), key_pair);
        Ok(self.secure_keys.get(key_id).unwrap())
    }

    /// Generate and store a new key pair (legacy)
    pub fn generate_key(&mut self, key_id: &str, key_type: KeyType) -> SigilResult<&SigilKeyPair> {
        let key_pair = SigilKeyPair::generate(key_id, key_type)?;
        self.keys.insert(key_id.to_string(), key_pair);
        Ok(self.keys.get(key_id).unwrap())
    }

    /// Get a key pair by ID
    pub fn get_key(&self, key_id: &str) -> Option<&SigilKeyPair> {
        self.keys.get(key_id)
    }

    /// Get a secure key pair by ID
    pub fn get_secure_key(&self, key_id: &str) -> Option<&SecureKeyPair> {
        self.secure_keys.get(key_id)
    }

    /// Sign data with a specific key
    pub fn sign_with_key(&self, key_id: &str, data: &[u8]) -> SigilResult<String> {
        // Try secure key first
        if let Some(secure_key) = self.secure_keys.get(key_id) {
            let master_key = self.master_key
                .ok_or_else(|| crate::errors::SigilError::auth("Master key not set".to_string()))?;
            return secure_key.sign(data, &master_key);
        }
        
        // Fall back to legacy key
        let key_pair = self
            .keys
            .get(key_id)
            .ok_or_else(|| crate::errors::SigilError::auth(format!("Key not found: {key_id}")))?;

        key_pair.sign(data)
    }

    /// Verify a signature with a specific key
    pub fn verify_with_key(&self, key_id: &str, data: &[u8], signature: &str) -> SigilResult<bool> {
        // Try secure key first
        if let Some(secure_key) = self.secure_keys.get(key_id) {
            return secure_key.verify(data, signature);
        }
        
        // Fall back to legacy key
        let key_pair = self
            .keys
            .get(key_id)
            .ok_or_else(|| crate::errors::SigilError::auth(format!("Key not found: {key_id}")))?;

        key_pair.verify(data, signature)
    }
}

impl Default for KeyManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Get the platform-appropriate home directory
pub fn get_home_dir() -> SigilResult<PathBuf> {
    // Try platform-specific environment variables
    let home = if cfg!(target_os = "windows") {
        std::env::var("USERPROFILE")
    } else {
        std::env::var("HOME")
    };

    match home {
        Ok(path) => Ok(PathBuf::from(path)),
        Err(_) => {
            // Fallback: try to get home directory from current user
            if let Some(home) = dirs::home_dir() {
                Ok(home)
            } else {
                Err(crate::errors::SigilError::io(
                    "getting home directory",
                    std::io::Error::new(std::io::ErrorKind::NotFound, "Home directory not found"),
                ))
            }
        }
    }
}

/// Get the secure key directory path for the current platform
pub fn get_secure_key_dir() -> SigilResult<PathBuf> {
    let home = get_home_dir()?;
    let mut key_dir = home;
    key_dir.push(".sigil");
    key_dir.push("keys");
    Ok(key_dir)
}

/// Ensure the secure key directory exists
pub fn ensure_secure_key_dir() -> SigilResult<PathBuf> {
    let key_dir = get_secure_key_dir()?;
    fs::create_dir_all(&key_dir)
        .map_err(|e| crate::errors::SigilError::io("creating secure key directory", e))?;
    Ok(key_dir)
}

/// Find a key file in secure locations
pub fn find_key_file(key_id: &str) -> Option<PathBuf> {
    // First check current directory
    let current_path = PathBuf::from(format!("{key_id}.json"));
    if current_path.exists() {
        return Some(current_path);
    }

    // Then check secure key directory
    if let Ok(mut secure_path) = get_secure_key_dir() {
        secure_path.push(format!("{key_id}.json"));
        if secure_path.exists() {
            return Some(secure_path);
        }
    }

    None
}

/// Get the default path for a key file
pub fn get_default_key_path(key_id: &str) -> SigilResult<PathBuf> {
    let key_dir = ensure_secure_key_dir()?;
    let mut key_path = key_dir;
    key_path.push(format!("{key_id}.json"));
    Ok(key_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_key_generation() {
        let master_key = [1u8; 32];
        let key_pair = SecureKeyPair::generate("test_secure_key", KeyType::LicenseSigning, &master_key).unwrap();
        assert_eq!(key_pair.key_id, "test_secure_key");
        assert!(!key_pair.public_key.is_empty());
        assert!(!key_pair.encrypted_private_key.is_empty());
    }

    #[test]
    fn test_secure_sign_and_verify() {
        let master_key = [1u8; 32];
        let key_pair = SecureKeyPair::generate("test_secure_key", KeyType::LicenseSigning, &master_key).unwrap();
        let data = b"Hello, Secure Sigil!";

        let signature = key_pair.sign(data, &master_key).unwrap();
        let is_valid = key_pair.verify(data, &signature).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_master_key_derivation() {
        let password = "test_password";
        let salt = [1u8; 32];
        
        let master_key = derive_master_key(password, &salt).unwrap();
        assert_eq!(master_key.len(), 32);
        
        // Same password and salt should produce same key
        let master_key2 = derive_master_key(password, &salt).unwrap();
        assert_eq!(master_key, master_key2);
        
        // Different password should produce different key
        let master_key3 = derive_master_key("different_password", &salt).unwrap();
        assert_ne!(master_key, master_key3);
    }

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
        let _key_pair = manager
            .generate_key("test_key", KeyType::LicenseSigning)
            .unwrap();

        let data = b"Test data";
        let signature = manager.sign_with_key("test_key", data).unwrap();
        let is_valid = manager
            .verify_with_key("test_key", data, &signature)
            .unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_secure_key_manager() {
        let mut manager = KeyManager::new();
        let master_key = [1u8; 32];
        manager.set_master_key(master_key);
        
        let _secure_key = manager
            .generate_secure_key("test_secure_key", KeyType::LicenseSigning)
            .unwrap();

        let data = b"Test secure data";
        let signature = manager.sign_with_key("test_secure_key", data).unwrap();
        let is_valid = manager
            .verify_with_key("test_secure_key", data, &signature)
            .unwrap();

        assert!(is_valid);
    }
}
