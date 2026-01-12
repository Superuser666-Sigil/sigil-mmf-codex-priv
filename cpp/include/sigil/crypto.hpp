#pragma once

#include "types.hpp"
#include <string>
#include <vector>
#include <array>
#include <memory>
#include <map>

namespace sigil::crypto
{

    // Type aliases for clarity
    using Bytes = std::vector<uint8_t>;
    using Ed25519PublicKey = std::array<uint8_t, 32>;
    using Ed25519SecretKey = std::array<uint8_t, 64>;
    using Ed25519Signature = std::array<uint8_t, 64>;
    using SHA256Hash = std::array<uint8_t, 32>;
    using AESKey = std::array<uint8_t, 32>;
    using AESNonce = std::array<uint8_t, 12>;

    /**
     * Ed25519 key pair for signing and verification
     * Maps to ed25519-dalek KeyPair from keys.rs
     */
    class Ed25519KeyPair
    {
    public:
        Ed25519PublicKey public_key;
        Ed25519SecretKey secret_key;

        /**
         * Generate a new random key pair
         */
        static Result<Ed25519KeyPair> generate();

        /**
         * Load key pair from seed bytes (32 bytes)
         */
        static Result<Ed25519KeyPair> from_seed(const std::array<uint8_t, 32> &seed);

        /**
         * Load from separate public/secret key bytes
         */
        static Result<Ed25519KeyPair> from_keys(
            const Ed25519PublicKey &public_key,
            const Ed25519SecretKey &secret_key);

        /**
         * Sign a message, returns 64-byte signature
         */
        Ed25519Signature sign(const Bytes &message) const;

        /**
         * Verify signature against message
         */
        static bool verify(
            const Bytes &message,
            const Ed25519Signature &signature,
            const Ed25519PublicKey &public_key);

        /**
         * Export to base64-encoded JSON (matches Rust format)
         */
        std::string to_json() const;

        /**
         * Import from base64-encoded JSON
         */
        static Result<Ed25519KeyPair> from_json(const std::string &json);
    };

    /**
     * AES-256-GCM encryption/decryption
     * Maps to aes-gcm usage in config_security.rs and canon_store_sled_encrypted.rs
     */
    class AES256GCM
    {
    public:
        /**
         * Encrypt plaintext with given key, returns nonce + ciphertext + tag
         * Output format: [12-byte nonce][ciphertext][16-byte tag]
         */
        static Result<Bytes> encrypt(
            const AESKey &key,
            const Bytes &plaintext,
            const Bytes &associated_data = {});

        /**
         * Decrypt ciphertext with given key
         * Input format: [12-byte nonce][ciphertext][16-byte tag]
         */
        static Result<Bytes> decrypt(
            const AESKey &key,
            const Bytes &ciphertext_with_nonce,
            const Bytes &associated_data = {});

        /**
         * Generate random AES-256 key
         */
        static AESKey generate_key();
    };

    /**
     * SHA-256 hashing
     */
    class SHA256
    {
    public:
        /**
         * Compute SHA-256 hash of data
         */
        static SHA256Hash hash(const Bytes &data);

        /**
         * Compute SHA-256 hash of string
         */
        static SHA256Hash hash(const std::string &data);

        /**
         * Convert hash to hex string
         */
        static std::string to_hex(const SHA256Hash &hash);

        /**
         * Parse hash from hex string
         */
        static Result<SHA256Hash> from_hex(const std::string &hex);
    };

    /**
     * Argon2id key derivation
     * Maps to argon2 usage in key_manager.rs
     */
    class Argon2
    {
    public:
        /**
         * Derive key from passphrase using Argon2id
         * @param passphrase Input passphrase
         * @param salt Salt (16 bytes recommended)
         * @param ops_limit Computational cost (3 = interactive, 4 = moderate, 5 = sensitive)
         * @param mem_limit Memory cost in bytes
         * @param key_len Output key length
         */
        static Result<Bytes> derive_key(
            const std::string &passphrase,
            const Bytes &salt,
            uint64_t ops_limit = 3,
            size_t mem_limit = 67108864, // 64 MiB
            size_t key_len = 32);
    };

    /**
     * Base64 encoding/decoding
     * Maps to base64 crate usage throughout Rust codebase
     */
    class Base64
    {
    public:
        /**
         * Encode bytes to base64 string (standard alphabet)
         */
        static std::string encode(const Bytes &data);

        /**
         * Decode base64 string to bytes
         */
        static Result<Bytes> decode(const std::string &encoded);

        /**
         * Encode to URL-safe base64 (no padding)
         */
        static std::string encode_url_safe(const Bytes &data);

        /**
         * Decode URL-safe base64
         */
        static Result<Bytes> decode_url_safe(const std::string &encoded);
    };

    /**
     * Cryptographically secure random number generation
     */
    class SecureRandom
    {
    public:
        /**
         * Fill buffer with cryptographically secure random bytes
         */
        static void fill_bytes(Bytes &buffer);

        /**
         * Generate N random bytes
         */
        static Bytes generate_bytes(size_t n);
    };

    // ========== Key Management (Phase 2B) ==========

    /**
     * Persistent Ed25519 key pair for Canon signing
     * Maps to CanonSigningKey in keys.rs
     */
    class CanonSigningKey
    {
    private:
        Ed25519KeyPair keypair;

    public:
        /**
         * Generate a new random signing key
         */
        static CanonSigningKey generate();

        /**
         * Load from base64-encoded private key string
         */
        static Result<CanonSigningKey> load_signing_key_b64(const std::string &b64);

        /**
         * Load from unencrypted JSON file (legacy format)
         */
        static Result<CanonSigningKey> load_from_file(const std::string &path);

        /**
         * Save to unencrypted JSON file (legacy format)
         */
        Result<void> save_to_file(const std::string &path, const std::string &purpose) const;

        /**
         * Load from encrypted JSON file with key index
         * Returns (key, key_index)
         */
        static Result<std::pair<CanonSigningKey, uint32_t>> load_encrypted(
            const std::string &path,
            const AESKey &encryption_key);

        /**
         * Save to encrypted JSON file
         */
        Result<void> save_encrypted(
            const std::string &path,
            const AESKey &encryption_key,
            uint32_t key_index,
            const std::string &purpose) const;

        /**
         * Get base64-encoded public key
         */
        std::string public_key_b64() const;

        /**
         * Get base64-encoded private key (use with caution!)
         */
        std::string private_key_b64() const;

        /**
         * Sign canonical bytes, returns (signature_b64, public_key_b64)
         */
        std::pair<std::string, std::string> sign_canonical_bytes(const Bytes &canonical_bytes) const;

        /**
         * Sign a record (same as sign_canonical_bytes for compatibility)
         */
        std::pair<std::string, std::string> sign_record(const Bytes &canonical_bytes) const;

        /**
         * Verify signature against canonical bytes
         */
        Result<void> verify_signature(const Bytes &canonical_bytes, const std::string &signature_b64) const;

        /**
         * Get the underlying keypair
         */
        const Ed25519KeyPair &get_keypair() const { return keypair; }

        /**
         * Create from existing keypair
         */
        static CanonSigningKey from_keypair(const Ed25519KeyPair &kp);
    };

    /**
     * Key store managing multiple key versions
     * Maps to KeyStore in keys.rs
     */
    class KeyStore
    {
    private:
        std::map<uint32_t, CanonSigningKey> keys;
        uint32_t current_key_index;

    public:
        /**
         * Create new empty key store
         */
        KeyStore();

        /**
         * Add a key to the store
         */
        void add_key(uint32_t key_index, const CanonSigningKey &key);

        /**
         * Get the current (latest) signing key
         */
        Result<CanonSigningKey> current_key() const;

        /**
         * Get a specific key by index (for verifying historical signatures)
         */
        Result<CanonSigningKey> get_key(uint32_t key_index) const;

        /**
         * Generate and add a new key, making it current
         * Returns the new key index
         */
        uint32_t rotate_key();

        /**
         * Get all key indices (sorted)
         */
        std::vector<uint32_t> key_indices() const;

        /**
         * Get the current key index
         */
        uint32_t current_key_index_value() const { return current_key_index; }

        /**
         * Load key store from encrypted files in a directory
         */
        static Result<KeyStore> load_from_directory(
            const std::string &dir_path,
            const AESKey &encryption_key);

        /**
         * Save all keys to encrypted files in a directory
         */
        Result<void> save_to_directory(
            const std::string &dir_path,
            const AESKey &encryption_key) const;
    };

    /**
     * Key management utilities with environment controls
     * Maps to KeyManager in keys.rs
     */
    class KeyManager
    {
    public:
        /**
         * Get the encryption key from environment (CANON_ENCRYPTION_KEY)
         */
        static Result<AESKey> get_encryption_key();

        /**
         * Get the key directory path from environment or default
         * Environment: CANON_KEY_DIR, default: "keys/encrypted"
         */
        static std::string get_key_directory();

        /**
         * Get or create a key store with encrypted storage
         */
        static Result<KeyStore> get_or_create_key_store();

        /**
         * Get or create the default Canon signing key (backward compatibility)
         */
        static Result<CanonSigningKey> get_or_create_canon_key();

        /**
         * Rotate keys in the key store
         * Returns new key index
         */
        static Result<uint32_t> rotate_keys(KeyStore &store);

        /**
         * Verify that a key pair is valid
         */
        static Result<void> verify_key_pair(const CanonSigningKey &key);

        /**
         * Verify a key store (test all keys)
         */
        static Result<void> verify_key_store(const KeyStore &store);

        /**
         * Get default key file path (legacy)
         * Environment: CANON_LEGACY_KEY_PATH, default: "keys/canon_signing_key.json"
         */
        static std::string default_key_path();

    private:
        /**
         * Try to migrate a legacy unencrypted key
         * Returns Some(KeyStore) if migration successful, None otherwise
         */
        static Result<std::optional<KeyStore>> try_migrate_legacy_key(const AESKey &encryption_key);
    };

} // namespace sigil::crypto
