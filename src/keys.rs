//! Persistent Ed25519 key management for Canon signing
//!
//! This module provides utilities for generating, loading, and managing
//! persistent Ed25519 signing keys for Canon record integrity.

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, OsRng},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

/// Errors that can occur during key operations
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Invalid key length: expected 32 bytes, got {0}")]
    InvalidKeyLength(usize),

    #[error("Key signature error: {0}")]
    Signature(#[from] ed25519_dalek::SignatureError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Invalid encryption key")]
    InvalidEncryptionKey,

    #[error("Key not found: {0}")]
    KeyNotFound(String),
}

/// A persistent Ed25519 key pair for Canon signing
#[derive(Debug, Clone)]
pub struct CanonSigningKey {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

/// Encrypted key storage format
#[derive(Serialize, Deserialize)]
struct EncryptedKeyData {
    /// Schema version for future compatibility
    version: u32,
    /// Base64-encoded encrypted private key
    encrypted_private_key_b64: String,
    /// Base64-encoded public key (not encrypted, used for verification)
    public_key_b64: String,
    /// Base64-encoded AES-GCM nonce
    nonce_b64: String,
    /// Key generation timestamp
    created_at: String,
    /// Key rotation index (for key versioning)
    key_index: u32,
    /// Key purpose/description
    purpose: String,
}

/// Legacy unencrypted key data for backwards compatibility
#[derive(Serialize, Deserialize)]
struct KeyData {
    /// Base64-encoded private key (32 bytes)
    private_key_b64: String,
    /// Base64-encoded public key (32 bytes)
    public_key_b64: String,
    /// Key generation timestamp
    created_at: String,
    /// Key purpose/description
    purpose: String,
}

/// Key store managing multiple key versions
#[derive(Debug, Clone)]
pub struct KeyStore {
    keys: std::collections::HashMap<u32, CanonSigningKey>,
    current_key_index: u32,
}

impl KeyStore {
    /// Create a new empty key store
    pub fn new() -> Self {
        Self {
            keys: std::collections::HashMap::new(),
            current_key_index: 0,
        }
    }

    /// Add a key to the store
    pub fn add_key(&mut self, key_index: u32, key: CanonSigningKey) {
        self.keys.insert(key_index, key);
        if key_index > self.current_key_index {
            self.current_key_index = key_index;
        }
    }

    /// Get the current (latest) signing key
    pub fn current_key(&self) -> Result<&CanonSigningKey, KeyError> {
        self.keys.get(&self.current_key_index).ok_or_else(|| {
            KeyError::KeyNotFound(format!("current key index {}", self.current_key_index))
        })
    }

    /// Get a specific key by index (for verifying historical signatures)
    pub fn get_key(&self, key_index: u32) -> Result<&CanonSigningKey, KeyError> {
        self.keys
            .get(&key_index)
            .ok_or_else(|| KeyError::KeyNotFound(format!("key index {}", key_index)))
    }

    /// Generate and add a new key, making it current
    pub fn rotate_key(&mut self) -> u32 {
        let new_index = self.current_key_index + 1;
        let new_key = CanonSigningKey::generate();
        self.add_key(new_index, new_key);
        new_index
    }

    /// Get all key indices
    pub fn key_indices(&self) -> Vec<u32> {
        let mut indices: Vec<u32> = self.keys.keys().copied().collect();
        indices.sort();
        indices
    }

    /// Get the current key index
    pub fn current_key_index(&self) -> u32 {
        self.current_key_index
    }

    /// Load a key store from encrypted files in a directory
    pub fn load_from_directory<P: AsRef<Path>>(
        dir_path: P,
        encryption_key: &[u8; 32],
    ) -> Result<Self, KeyError> {
        let mut store = Self::new();
        let dir = fs::read_dir(dir_path)?;

        for entry in dir {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("json")
                && let Ok((key, key_index)) = CanonSigningKey::load_encrypted(&path, encryption_key)
            {
                store.add_key(key_index, key);
            }
        }

        if store.keys.is_empty() {
            return Err(KeyError::KeyNotFound(
                "No valid keys found in directory".to_string(),
            ));
        }

        Ok(store)
    }

    /// Save all keys in the store to encrypted files in a directory
    pub fn save_to_directory<P: AsRef<Path>>(
        &self,
        dir_path: P,
        encryption_key: &[u8; 32],
    ) -> Result<(), KeyError> {
        let dir_path = dir_path.as_ref();
        fs::create_dir_all(dir_path)?;

        for (&key_index, key) in &self.keys {
            let filename = format!("canon_key_{:04}.json", key_index);
            let key_path = dir_path.join(filename);
            let purpose = if key_index == self.current_key_index {
                "Canon record signing (current)"
            } else {
                "Canon record signing (historical)"
            };
            key.save_encrypted(&key_path, encryption_key, key_index, purpose)?;
        }

        Ok(())
    }
}

impl Default for KeyStore {
    fn default() -> Self { Self::new() }
}

impl CanonSigningKey {
    /// Generate a new random Ed25519 key pair
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();

        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Load a signing key from a base64-encoded private key string
    pub fn load_signing_key_b64(b64: &str) -> Result<Self, KeyError> {
        let sk_bytes = B64.decode(b64)?;
        if sk_bytes.len() != 32 {
            return Err(KeyError::InvalidKeyLength(sk_bytes.len()));
        }

        let sk_array: [u8; 32] = sk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| KeyError::InvalidKeyLength(sk_bytes.len()))?;

        let signing_key = SigningKey::from_bytes(&sk_array);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Load a key pair from a JSON file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, KeyError> {
        let content = fs::read_to_string(path)?;
        let key_data: KeyData = serde_json::from_str(&content)?;
        Self::load_signing_key_b64(&key_data.private_key_b64)
    }

    /// Save the key pair to a JSON file (legacy, unencrypted)
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P, purpose: &str) -> Result<(), KeyError> {
        let key_data = KeyData {
            private_key_b64: B64.encode(self.signing_key.to_bytes()),
            public_key_b64: B64.encode(self.verifying_key.to_bytes()),
            created_at: chrono::Utc::now().to_rfc3339(),
            purpose: purpose.to_string(),
        };

        let json = serde_json::to_string_pretty(&key_data)?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Save the key pair to an encrypted JSON file
    pub fn save_encrypted<P: AsRef<Path>>(
        &self,
        path: P,
        encryption_key: &[u8; 32],
        key_index: u32,
        purpose: &str,
    ) -> Result<(), KeyError> {
        if encryption_key.len() != 32 {
            return Err(KeyError::InvalidEncryptionKey);
        }

        // Generate a random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Create AES-GCM cipher
        let cipher = Aes256Gcm::new_from_slice(encryption_key)
            .map_err(|e| KeyError::Encryption(e.to_string()))?;

        // Encrypt the private key
        let private_key_bytes = self.signing_key.to_bytes();
        let encrypted_private_key = cipher
            .encrypt(nonce, private_key_bytes.as_ref())
            .map_err(|e| KeyError::Encryption(e.to_string()))?;

        let encrypted_data = EncryptedKeyData {
            version: 1,
            encrypted_private_key_b64: B64.encode(&encrypted_private_key),
            public_key_b64: B64.encode(self.verifying_key.to_bytes()),
            nonce_b64: B64.encode(nonce_bytes),
            created_at: chrono::Utc::now().to_rfc3339(),
            key_index,
            purpose: purpose.to_string(),
        };

        let json = serde_json::to_string_pretty(&encrypted_data)?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Load a key pair from an encrypted JSON file
    pub fn load_encrypted<P: AsRef<Path>>(
        path: P,
        encryption_key: &[u8; 32],
    ) -> Result<(Self, u32), KeyError> {
        let content = fs::read_to_string(path)?;
        let encrypted_data: EncryptedKeyData = serde_json::from_str(&content)?;

        // Create AES-GCM cipher
        let cipher = Aes256Gcm::new_from_slice(encryption_key)
            .map_err(|e| KeyError::Encryption(e.to_string()))?;

        // Decode nonce and encrypted private key
        let nonce_bytes = B64.decode(&encrypted_data.nonce_b64)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted_private_key = B64.decode(&encrypted_data.encrypted_private_key_b64)?;

        // Decrypt the private key
        let private_key_bytes = cipher
            .decrypt(nonce, encrypted_private_key.as_ref())
            .map_err(|e| KeyError::Encryption(e.to_string()))?;

        let key_len = private_key_bytes.len();
        if key_len != 32 {
            return Err(KeyError::InvalidKeyLength(key_len));
        }

        let sk_array: [u8; 32] = private_key_bytes
            .try_into()
            .map_err(|_| KeyError::InvalidKeyLength(key_len))?;

        let signing_key = SigningKey::from_bytes(&sk_array);
        let verifying_key = signing_key.verifying_key();

        // Verify public key matches
        let expected_pk = B64.encode(verifying_key.to_bytes());
        if expected_pk != encrypted_data.public_key_b64 {
            return Err(KeyError::Encryption("Public key mismatch".to_string()));
        }

        let key = Self {
            signing_key,
            verifying_key,
        };

        Ok((key, encrypted_data.key_index))
    }

    /// Get the base64-encoded public key
    pub fn public_key_b64(&self) -> String {
        B64.encode(self.verifying_key.to_bytes())
    }

    /// Get the base64-encoded private key (use with caution!)
    pub fn private_key_b64(&self) -> String {
        B64.encode(self.signing_key.to_bytes())
    }

    /// Sign canonical bytes and return (signature_b64, public_key_b64)
    pub fn sign_canonical_bytes(&self, canonical_bytes: &[u8]) -> (String, String) {
        let signature = self.signing_key.sign(canonical_bytes);
        let sig_b64 = B64.encode(signature.to_bytes());
        let pk_b64 = self.public_key_b64();
        (sig_b64, pk_b64)
    }

    /// Verify a signature against canonical bytes
    pub fn verify_signature(
        &self,
        canonical_bytes: &[u8],
        signature_b64: &str,
    ) -> Result<(), KeyError> {
        let sig_bytes = B64.decode(signature_b64)?;
        let sig_len = sig_bytes.len();
        let signature = Signature::from_bytes(
            &sig_bytes
                .try_into()
                .map_err(|_| KeyError::InvalidKeyLength(sig_len))?,
        );

        self.verifying_key.verify(canonical_bytes, &signature)?;
        Ok(())
    }

    /// Sign a record using the sketch you provided
    pub fn sign_record(&self, canonical_bytes: &[u8]) -> (String, String) {
        // Compute hash for reference (though we sign the canonical bytes directly)
        let _hash = Sha256::digest(canonical_bytes);

        // Sign the canonical bytes
        let sig = self.signing_key.sign(canonical_bytes).to_bytes();
        let pk = self.verifying_key.as_bytes();

        (B64.encode(sig), B64.encode(pk))
    }
}

/// Key management utilities with environment controls and rotation
pub struct KeyManager;

impl KeyManager {
    /// Get the encryption key from environment or generate a default one
    ///
    /// Environment variables:
    /// - CANON_ENCRYPTION_KEY: Base64-encoded 32-byte AES key
    /// - CANON_KEY_DIR: Directory for encrypted key storage
    /// - CANON_LEGACY_KEY_PATH: Path to legacy unencrypted key (for migration)
    pub fn get_encryption_key() -> Result<[u8; 32], KeyError> {
        if let Ok(key_b64) = std::env::var("CANON_ENCRYPTION_KEY") {
            let key_bytes = B64
                .decode(&key_b64)
                .map_err(|_| KeyError::InvalidEncryptionKey)?;
            if key_bytes.len() != 32 {
                return Err(KeyError::InvalidEncryptionKey);
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);
            return Ok(key);
        }

        log::warn!(
            "No CANON_ENCRYPTION_KEY environment variable set, using default key for development"
        );
        log::warn!("This is NOT secure for production use!");

        // Default key for development only - NOT secure for production!
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(b"sigil_dev_key_16");
        key[16..].copy_from_slice(b"bytes_for_aes256");
        Ok(key)
    }

    /// Get the key directory path from environment or default
    pub fn get_key_directory() -> std::path::PathBuf {
        std::env::var("CANON_KEY_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from("keys/encrypted"))
    }

    /// Get or create a key store with encrypted storage
    pub fn get_or_create_key_store() -> Result<KeyStore, KeyError> {
        let encryption_key = Self::get_encryption_key()?;
        let key_dir = Self::get_key_directory();

        // Try to load existing encrypted key store
        if key_dir.exists() {
            match KeyStore::load_from_directory(&key_dir, &encryption_key) {
                Ok(store) => {
                    log::info!("Loaded encrypted key store from {:?}", key_dir);
                    return Ok(store);
                }
                Err(e) => {
                    log::warn!(
                        "Failed to load encrypted key store: {}, creating new one",
                        e
                    );
                }
            }
        }

        // Try to migrate legacy key if it exists
        if let Some(legacy_store) = Self::try_migrate_legacy_key(&encryption_key)? {
            log::info!("Migrated legacy key to encrypted storage");
            legacy_store.save_to_directory(&key_dir, &encryption_key)?;
            return Ok(legacy_store);
        }

        // Create new key store with initial key
        log::info!("Creating new encrypted key store at {:?}", key_dir);
        let mut store = KeyStore::new();
        store.rotate_key(); // Creates key index 1
        store.save_to_directory(&key_dir, &encryption_key)?;

        Ok(store)
    }

    /// Try to migrate a legacy unencrypted key to the new format
    fn try_migrate_legacy_key(_encryption_key: &[u8; 32]) -> Result<Option<KeyStore>, KeyError> {
        let legacy_path = std::env::var("CANON_LEGACY_KEY_PATH")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from("keys/canon_signing_key.json"));

        if !legacy_path.exists() {
            return Ok(None);
        }

        log::info!("Migrating legacy key from {:?}", legacy_path);

        // Load the legacy key
        let legacy_key = CanonSigningKey::load_from_file(&legacy_path)?;

        // Create a new key store and add the legacy key as index 1
        let mut store = KeyStore::new();
        store.add_key(1, legacy_key);

        // Backup the legacy key file
        let backup_path = legacy_path.with_extension("json.legacy_backup");
        fs::copy(&legacy_path, &backup_path)?;
        log::info!("Backed up legacy key to {:?}", backup_path);

        Ok(Some(store))
    }

    /// Rotate keys in the key store
    pub fn rotate_keys(store: &mut KeyStore) -> Result<u32, KeyError> {
        let new_index = store.rotate_key();
        let encryption_key = Self::get_encryption_key()?;
        let key_dir = Self::get_key_directory();

        store.save_to_directory(&key_dir, &encryption_key)?;
        log::info!("Rotated to new key index: {}", new_index);

        Ok(new_index)
    }

    /// Get or create the default Canon signing key (backward compatibility)
    pub fn get_or_create_canon_key() -> Result<CanonSigningKey, KeyError> {
        let store = Self::get_or_create_key_store()?;
        Ok(store.current_key()?.clone())
    }

    /// Get the default key file path (legacy)
    pub fn default_key_path() -> std::path::PathBuf {
        std::env::var("CANON_LEGACY_KEY_PATH")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from("keys/canon_signing_key.json"))
    }

    /// Verify that a key pair is valid
    pub fn verify_key_pair(key: &CanonSigningKey) -> Result<(), KeyError> {
        let test_data = b"test canonical data for key verification";
        let (sig_b64, _pk_b64) = key.sign_canonical_bytes(test_data);
        key.verify_signature(test_data, &sig_b64)?;
        Ok(())
    }

    /// Verify a key store (test all keys)
    pub fn verify_key_store(store: &KeyStore) -> Result<(), KeyError> {
        for &key_index in &store.key_indices() {
            let key = store.get_key(key_index)?;
            Self::verify_key_pair(key).map_err(|e| {
                KeyError::Encryption(format!("Key {} verification failed: {}", key_index, e))
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_key_generation_and_signing() {
        let key = CanonSigningKey::generate();

        let test_data = b"test canonical record data";
        let (sig_b64, pk_b64) = key.sign_canonical_bytes(test_data);

        // Verify the signature
        assert!(key.verify_signature(test_data, &sig_b64).is_ok());

        // Verify public key format
        assert!(!pk_b64.is_empty());
        assert!(B64.decode(&pk_b64).unwrap().len() == 32);
    }

    #[test]
    fn test_key_serialization() {
        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("test_key.json");

        let original_key = CanonSigningKey::generate();
        let original_pk = original_key.public_key_b64();

        // Save and reload
        original_key.save_to_file(&key_path, "test").unwrap();
        let loaded_key = CanonSigningKey::load_from_file(&key_path).unwrap();

        // Should have same public key
        assert_eq!(original_pk, loaded_key.public_key_b64());

        // Should be able to sign and verify
        let test_data = b"test data for loaded key";
        let (sig_b64, _) = loaded_key.sign_canonical_bytes(test_data);
        assert!(loaded_key.verify_signature(test_data, &sig_b64).is_ok());
    }

    #[test]
    fn test_key_manager_isolated() {
        // Use a unique environment variable name to avoid interference
        let temp_dir = tempdir().unwrap();
        let key_dir = temp_dir.path().join("test_isolated_keys");
        let unique_env_key = format!("TEST_CANON_KEY_DIR_{}", std::process::id());

        // Temporarily override the get_key_directory method by setting a unique env var
        unsafe {
            std::env::set_var(&unique_env_key, key_dir.to_str().unwrap());
        }

        // Create a temporary modified KeyManager that uses our unique env var
        struct TestKeyManager;
        impl TestKeyManager {
            fn get_key_directory_isolated(env_key: &str) -> std::path::PathBuf {
                std::env::var(env_key)
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(|_| std::path::PathBuf::from("keys/test_fallback"))
            }

            fn get_or_create_key_store_isolated(env_key: &str) -> Result<KeyStore, KeyError> {
                let encryption_key = KeyManager::get_encryption_key()?;
                let key_dir = Self::get_key_directory_isolated(env_key);

                // Try to load existing encrypted key store
                if key_dir.exists() {
                    match KeyStore::load_from_directory(&key_dir, &encryption_key) {
                        Ok(store) => {
                            return Ok(store);
                        }
                        Err(_) => {
                            // Continue to create new store
                        }
                    }
                }

                // Create new key store with initial key
                let mut store = KeyStore::new();
                store.rotate_key(); // Creates key index 1
                store.save_to_directory(&key_dir, &encryption_key)?;

                Ok(store)
            }
        }

        // First call should generate a new key store
        let store1 = TestKeyManager::get_or_create_key_store_isolated(&unique_env_key).unwrap();
        let key1 = store1.current_key().unwrap().clone();
        assert!(KeyManager::verify_key_pair(&key1).is_ok());

        // Second call should load the same key from the encrypted store
        let store2 = TestKeyManager::get_or_create_key_store_isolated(&unique_env_key).unwrap();
        let key2 = store2.current_key().unwrap().clone();
        assert_eq!(key1.public_key_b64(), key2.public_key_b64());

        // Clean up environment variable
        unsafe {
            std::env::remove_var(&unique_env_key);
        }
    }

    #[test]
    fn test_encrypted_key_storage() {
        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("encrypted_key.json");

        let original_key = CanonSigningKey::generate();
        let original_pk = original_key.public_key_b64();

        // Generate encryption key
        let mut encryption_key = [0u8; 32];
        OsRng.fill_bytes(&mut encryption_key);

        // Save encrypted
        original_key
            .save_encrypted(&key_path, &encryption_key, 1, "test key")
            .unwrap();

        // Load encrypted
        let (loaded_key, key_index) =
            CanonSigningKey::load_encrypted(&key_path, &encryption_key).unwrap();

        // Should have same public key and correct index
        assert_eq!(original_pk, loaded_key.public_key_b64());
        assert_eq!(key_index, 1);

        // Should be able to sign and verify
        let test_data = b"test data for encrypted key";
        let (sig_b64, _) = loaded_key.sign_canonical_bytes(test_data);
        assert!(loaded_key.verify_signature(test_data, &sig_b64).is_ok());
    }

    #[test]
    fn test_key_store_rotation() {
        let mut store = KeyStore::new();

        // Rotate first key
        let index1 = store.rotate_key();
        assert_eq!(index1, 1);
        assert_eq!(store.current_key_index(), 1);

        // Store should have one key
        assert_eq!(store.key_indices(), vec![1]);

        // Get current key
        let key1 = store.current_key().unwrap().clone();

        // Rotate second key
        let index2 = store.rotate_key();
        assert_eq!(index2, 2);
        assert_eq!(store.current_key_index(), 2);

        // Store should have two keys
        let mut indices = store.key_indices();
        indices.sort();
        assert_eq!(indices, vec![1, 2]);

        // Should be able to get both keys
        let historical_key = store.get_key(1).unwrap();
        let current_key = store.current_key().unwrap();

        // Keys should be different
        assert_ne!(
            historical_key.public_key_b64(),
            current_key.public_key_b64()
        );
        assert_eq!(historical_key.public_key_b64(), key1.public_key_b64());
    }

    #[test]
    fn test_key_store_directory_operations() {
        let temp_dir = tempdir().unwrap();
        let key_dir = temp_dir.path().join("key_store");

        // Generate encryption key
        let mut encryption_key = [0u8; 32];
        OsRng.fill_bytes(&mut encryption_key);

        // Create a key store with multiple keys
        let mut original_store = KeyStore::new();
        original_store.rotate_key(); // index 1
        original_store.rotate_key(); // index 2
        original_store.rotate_key(); // index 3

        let original_current_pk = original_store.current_key().unwrap().public_key_b64();

        // Save to directory
        original_store
            .save_to_directory(&key_dir, &encryption_key)
            .unwrap();

        // Verify files were created
        assert!(key_dir.exists());
        let entries: Vec<_> = fs::read_dir(&key_dir).unwrap().collect();
        assert_eq!(entries.len(), 3); // 3 key files

        // Load from directory
        let loaded_store = KeyStore::load_from_directory(&key_dir, &encryption_key).unwrap();

        // Should have same keys and current key
        assert_eq!(loaded_store.key_indices(), original_store.key_indices());
        assert_eq!(
            loaded_store.current_key_index(),
            original_store.current_key_index()
        );
        assert_eq!(
            loaded_store.current_key().unwrap().public_key_b64(),
            original_current_pk
        );

        // All keys should be verifiable
        assert!(KeyManager::verify_key_store(&loaded_store).is_ok());
    }

    #[test]
    fn test_legacy_key_migration() {
        let temp_dir = tempdir().unwrap();
        let legacy_path = temp_dir.path().join("legacy_key.json");
        let key_dir = temp_dir.path().join("encrypted_keys");

        // Create a legacy key
        let legacy_key = CanonSigningKey::generate();
        let legacy_pk = legacy_key.public_key_b64();
        legacy_key.save_to_file(&legacy_path, "legacy key").unwrap();

        // Set environment variables for testing
        unsafe {
            std::env::set_var("CANON_LEGACY_KEY_PATH", legacy_path.to_str().unwrap());
            std::env::set_var("CANON_KEY_DIR", key_dir.to_str().unwrap());
        }

        // Create key store (should migrate legacy key)
        let store = KeyManager::get_or_create_key_store().unwrap();

        // Should have migrated the legacy key as index 1
        assert_eq!(store.current_key_index(), 1);
        assert_eq!(store.current_key().unwrap().public_key_b64(), legacy_pk);

        // Backup file should exist
        let backup_path = legacy_path.with_extension("json.legacy_backup");
        assert!(backup_path.exists());

        // Encrypted key directory should exist
        assert!(key_dir.exists());

        // Clean up environment variables
        unsafe {
            std::env::remove_var("CANON_LEGACY_KEY_PATH");
            std::env::remove_var("CANON_KEY_DIR");
        }
    }

    #[test]
    fn test_rotation_preserves_historical_verification() {
        let temp_dir = tempdir().unwrap();
        let key_dir = temp_dir.path().join("rotation_test");

        // Generate encryption key
        let mut encryption_key = [0u8; 32];
        OsRng.fill_bytes(&mut encryption_key);

        // Create store and sign data with first key
        let mut store = KeyStore::new();
        store.rotate_key(); // index 1

        let test_data = b"important historical data";
        let key1 = store.current_key().unwrap();
        let (sig1_b64, pk1_b64) = key1.sign_canonical_bytes(test_data);

        // Rotate to new key
        store.rotate_key(); // index 2
        let key2 = store.current_key().unwrap();
        let (sig2_b64, pk2_b64) = key2.sign_canonical_bytes(test_data);

        // Keys should be different
        assert_ne!(pk1_b64, pk2_b64);

        // Save and reload store
        store.save_to_directory(&key_dir, &encryption_key).unwrap();
        let reloaded_store = KeyStore::load_from_directory(&key_dir, &encryption_key).unwrap();

        // Should be able to verify both signatures with reloaded store
        let historical_key = reloaded_store.get_key(1).unwrap();
        let current_key = reloaded_store.get_key(2).unwrap();

        assert!(
            historical_key
                .verify_signature(test_data, &sig1_b64)
                .is_ok()
        );
        assert!(current_key.verify_signature(test_data, &sig2_b64).is_ok());

        // Cross-verification should fail
        assert!(
            historical_key
                .verify_signature(test_data, &sig2_b64)
                .is_err()
        );
        assert!(current_key.verify_signature(test_data, &sig1_b64).is_err());
    }
}
