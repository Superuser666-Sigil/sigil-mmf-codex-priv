//! Comprehensive tests for Ed25519 key lifecycle management

use crate::keys::KeyManager;
use base64::Engine;
use rand;
use sha2::Digest;
use temp_env;
use tempfile::TempDir;
use tracing::info;

#[test]
fn test_key_manager_integration() {
    let temp_dir = TempDir::new().expect("should create temp dir");
    let custom_key_dir = temp_dir.path().join("manager_test");
    let unique_id = format!("MGR_{}", rand::random::<u64>());

    let test_encryption_key = create_test_encryption_key(&unique_id);
    let encryption_key_b64 = Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        test_encryption_key,
    );

    // Safe environment variable management using temp_env
    temp_env::with_vars(
        vec![
            (
                "CANON_KEY_DIR",
                Some(custom_key_dir.to_str().expect("utf-8 path")),
            ),
            ("CANON_ENCRYPTION_KEY", Some(&encryption_key_b64)),
        ],
        || {
            // Test KeyManager methods
            let retrieved_key =
                KeyManager::dev_key_for_testing().expect("should get encryption key");
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

            info!("✅ KeyManager integration test passed");
        },
    );
}

fn create_test_encryption_key(unique_id: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    let seed = format!("test_key_{unique_id}");
    let hash = sha2::Sha256::digest(seed.as_bytes());
    key.copy_from_slice(&hash[..32]);
    key
}
