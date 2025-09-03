//! Comprehensive tests for Ed25519 key lifecycle management

use crate::keys::{CanonSigningKey, KeyManager, KeyStore};
use sha2::Digest;
use std::env;
use tempfile::TempDir;

#[test]
fn test_complete_key_lifecycle() {
    let temp_dir = TempDir::new().expect("should create temp dir");
    let key_dir = temp_dir.path().join("lifecycle_test_keys");
    let unique_id = format!("TEST_{}", rand::random::<u64>());

    // Step 1: Test initial key store creation
    let encryption_key = create_test_encryption_key(&unique_id);
    let mut initial_store = KeyStore::new();

    assert_eq!(
        initial_store.current_key_index(),
        0,
        "new store should start at index 0"
    );

    let new_index = initial_store.rotate_key();
    assert_eq!(new_index, 1, "first key should have index 1");

    // Step 2: Test key persistence
    initial_store
        .save_to_directory(&key_dir, &encryption_key)
        .expect("should save key store");

    // Step 3: Test key loading
    let loaded_store =
        KeyStore::load_from_directory(&key_dir, &encryption_key).expect("should load key store");

    assert_eq!(
        loaded_store.current_key_index(),
        1,
        "loaded store should match"
    );

    // Step 4: Test key rotation
    let mut rotating_store = loaded_store;
    let old_key_pubkey = rotating_store.current_key().unwrap().public_key_b64();

    let rotation_index = rotating_store.rotate_key();
    assert_eq!(rotation_index, 2, "rotated key should have index 2");

    let new_key_pubkey = rotating_store.current_key().unwrap().public_key_b64();
    assert_ne!(
        old_key_pubkey, new_key_pubkey,
        "rotated key should be different"
    );

    // Step 5: Test historical key access
    let historical_key = rotating_store
        .get_key(1)
        .expect("should access historical key");
    assert_eq!(
        historical_key.public_key_b64(),
        old_key_pubkey,
        "historical key should match original"
    );

    println!("✅ Complete key lifecycle test passed");
}

#[test]
fn test_key_encryption_security() {
    let temp_dir = TempDir::new().expect("should create temp dir");
    let key_path = temp_dir.path().join("security_test.json");
    let unique_id = format!("SEC_{}", rand::random::<u64>());

    let test_key = CanonSigningKey::generate();
    let encryption_key = create_test_encryption_key(&unique_id);

    // Save encrypted
    test_key
        .save_encrypted(&key_path, &encryption_key, 1, "test key")
        .expect("should save encrypted");

    // Verify encrypted format
    let file_contents = std::fs::read_to_string(&key_path).expect("should read file");
    assert!(
        file_contents.contains("encrypted_private_key_b64"),
        "should use encrypted format"
    );
    assert!(
        file_contents.contains("nonce_b64"),
        "should contain AES-GCM nonce"
    );

    // Test decryption
    let (reloaded_key, key_index) = CanonSigningKey::load_encrypted(&key_path, &encryption_key)
        .expect("should load encrypted key");

    assert_eq!(key_index, 1, "key index should be preserved");
    assert_eq!(
        test_key.public_key_b64(),
        reloaded_key.public_key_b64(),
        "public key should match"
    );

    // Test signature compatibility
    let test_data = b"encryption test";
    let original_sig = test_key.sign_record(test_data);
    let reloaded_sig = reloaded_key.sign_record(test_data);

    test_key
        .verify_signature(test_data, &reloaded_sig.0)
        .expect("should cross-verify");
    reloaded_key
        .verify_signature(test_data, &original_sig.0)
        .expect("should cross-verify");

    println!("✅ Key encryption security test passed");
}

#[test]
fn test_key_manager_integration() {
    let temp_dir = TempDir::new().expect("should create temp dir");
    let custom_key_dir = temp_dir.path().join("manager_test");
    let unique_id = format!("MGR_{}", rand::random::<u64>());

    let test_encryption_key = create_test_encryption_key(&unique_id);
    let encryption_key_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &test_encryption_key,
    );

    // Set test environment
    let _guard = unsafe {
        TestEnvironmentGuard::new(&[
            ("CANON_KEY_DIR", custom_key_dir.to_str().unwrap()),
            ("CANON_ENCRYPTION_KEY", &encryption_key_b64),
        ])
    };

    // Test KeyManager methods
    let retrieved_key = KeyManager::get_encryption_key().expect("should get encryption key");
    assert_eq!(
        retrieved_key, test_encryption_key,
        "should use environment key"
    );

    let key_directory = KeyManager::get_key_directory();
    assert_eq!(
        key_directory, custom_key_dir,
        "should use environment directory"
    );

    // Test key store creation
    let store = KeyManager::get_or_create_key_store().expect("should create store");
    assert_eq!(store.current_key_index(), 1, "should create initial key");

    // Test canon key access
    let canon_key = KeyManager::get_or_create_canon_key().expect("should get canon key");
    let test_message = b"manager test";
    let signature = canon_key.sign_record(test_message);
    canon_key
        .verify_signature(test_message, &signature.0)
        .expect("should verify");

    println!("✅ KeyManager integration test passed");
}

fn create_test_encryption_key(unique_id: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    let seed = format!("test_key_{}", unique_id);
    let hash = sha2::Sha256::digest(seed.as_bytes());
    key.copy_from_slice(&hash[..32]);
    key
}

struct TestEnvironmentGuard {
    vars: Vec<(String, Option<String>)>,
}

impl TestEnvironmentGuard {
    unsafe fn new(env_vars: &[(&str, &str)]) -> Self {
        let mut vars = Vec::new();
        for (key, value) in env_vars {
            let original = env::var(key).ok();
            vars.push((key.to_string(), original));
            env::set_var(key, value);
        }
        Self { vars }
    }
}

impl Drop for TestEnvironmentGuard {
    fn drop(&mut self) {
        for (key, original_value) in &self.vars {
            unsafe {
                match original_value {
                    Some(value) => env::set_var(key, value),
                    None => env::remove_var(key),
                }
            }
        }
    }
}
