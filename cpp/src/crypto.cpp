#include "sigil/crypto.hpp"
#include <sodium.h>
#include <nlohmann/json.hpp>
#include <format>
#include <cstring>
#include <fstream>
#include <filesystem>
#include <chrono>

using json = nlohmann::json;

namespace sigil::crypto
{

    // Initialize libsodium on library load
    static struct SodiumInitializer
    {
        SodiumInitializer()
        {
            if (sodium_init() < 0)
            {
                throw std::runtime_error("Failed to initialize libsodium");
            }
        }
    } sodium_initializer;

    // ============================================================================
    // Ed25519KeyPair Implementation
    // ============================================================================

    Result<Ed25519KeyPair> Ed25519KeyPair::generate()
    {
        Ed25519KeyPair keypair;

        if (crypto_sign_keypair(keypair.public_key.data(), keypair.secret_key.data()) != 0)
        {
            return std::unexpected(SigilError::crypto("Failed to generate Ed25519 keypair"));
        }

        return keypair;
    }

    Result<Ed25519KeyPair> Ed25519KeyPair::from_seed(const std::array<uint8_t, 32> &seed)
    {
        Ed25519KeyPair keypair;

        if (crypto_sign_seed_keypair(keypair.public_key.data(), keypair.secret_key.data(), seed.data()) != 0)
        {
            return std::unexpected(SigilError::crypto("Failed to derive Ed25519 keypair from seed"));
        }

        return keypair;
    }

    Result<Ed25519KeyPair> Ed25519KeyPair::from_keys(
        const Ed25519PublicKey &public_key,
        const Ed25519SecretKey &secret_key)
    {
        Ed25519KeyPair keypair;
        keypair.public_key = public_key;
        keypair.secret_key = secret_key;

        // Verify the key pair is valid by checking public key matches secret key
        Ed25519PublicKey derived_pubkey;
        if (crypto_sign_ed25519_sk_to_pk(derived_pubkey.data(), secret_key.data()) != 0)
        {
            return std::unexpected(SigilError::crypto("Invalid secret key"));
        }

        if (std::memcmp(public_key.data(), derived_pubkey.data(), 32) != 0)
        {
            return std::unexpected(SigilError::crypto("Public key does not match secret key"));
        }

        return keypair;
    }

    Ed25519Signature Ed25519KeyPair::sign(const Bytes &message) const
    {
        Ed25519Signature signature;
        unsigned long long sig_len;

        crypto_sign_detached(
            signature.data(),
            &sig_len,
            message.data(),
            message.size(),
            secret_key.data());

        return signature;
    }

    bool Ed25519KeyPair::verify(
        const Bytes &message,
        const Ed25519Signature &signature,
        const Ed25519PublicKey &public_key)
    {
        return crypto_sign_verify_detached(
                   signature.data(),
                   message.data(),
                   message.size(),
                   public_key.data()) == 0;
    }

    std::string Ed25519KeyPair::to_json() const
    {
        json j = {
            {"public_key", Base64::encode(Bytes(public_key.begin(), public_key.end()))},
            {"secret_key", Base64::encode(Bytes(secret_key.begin(), secret_key.end()))}};
        return j.dump(2);
    }

    Result<Ed25519KeyPair> Ed25519KeyPair::from_json(const std::string &json_str)
    {
        try
        {
            auto j = json::parse(json_str);

            auto pub_result = Base64::decode(j.at("public_key").get<std::string>());
            if (!pub_result)
                return std::unexpected(pub_result.error());

            auto sec_result = Base64::decode(j.at("secret_key").get<std::string>());
            if (!sec_result)
                return std::unexpected(sec_result.error());

            if (pub_result->size() != 32)
            {
                return std::unexpected(SigilError::crypto("Invalid public key length"));
            }
            if (sec_result->size() != 64)
            {
                return std::unexpected(SigilError::crypto("Invalid secret key length"));
            }

            Ed25519PublicKey pubkey;
            Ed25519SecretKey seckey;
            std::copy(pub_result->begin(), pub_result->end(), pubkey.begin());
            std::copy(sec_result->begin(), sec_result->end(), seckey.begin());

            return Ed25519KeyPair::from_keys(pubkey, seckey);
        }
        catch (const json::exception &e)
        {
            return std::unexpected(SigilError::crypto(
                std::format("Failed to parse keypair JSON: {}", e.what())));
        }
    }

    // ============================================================================
    // AES256GCM Implementation
    // ============================================================================

    Result<Bytes> AES256GCM::encrypt(
        const AESKey &key,
        const Bytes &plaintext,
        const Bytes &associated_data)
    {
        // Generate random nonce
        AESNonce nonce;
        randombytes_buf(nonce.data(), nonce.size());

        // Allocate output: nonce + ciphertext + tag
        Bytes output(nonce.size() + plaintext.size() + crypto_aead_aes256gcm_ABYTES);

        // Copy nonce to output
        std::copy(nonce.begin(), nonce.end(), output.begin());

        unsigned long long ciphertext_len;
        if (crypto_aead_aes256gcm_encrypt(
                output.data() + nonce.size(), // ciphertext output
                &ciphertext_len,
                plaintext.data(),
                plaintext.size(),
                associated_data.data(),
                associated_data.size(),
                nullptr, // nsec (not used)
                nonce.data(),
                key.data()) != 0)
        {
            return std::unexpected(SigilError::crypto("AES-256-GCM encryption failed"));
        }

        // Resize to actual output size
        output.resize(nonce.size() + ciphertext_len);

        return output;
    }

    Result<Bytes> AES256GCM::decrypt(
        const AESKey &key,
        const Bytes &ciphertext_with_nonce,
        const Bytes &associated_data)
    {
        if (ciphertext_with_nonce.size() < 12 + crypto_aead_aes256gcm_ABYTES)
        {
            return std::unexpected(SigilError::crypto("Ciphertext too short"));
        }

        // Extract nonce
        AESNonce nonce;
        std::copy(ciphertext_with_nonce.begin(), ciphertext_with_nonce.begin() + 12, nonce.begin());

        // Decrypt
        Bytes plaintext(ciphertext_with_nonce.size() - 12 - crypto_aead_aes256gcm_ABYTES);
        unsigned long long plaintext_len;

        if (crypto_aead_aes256gcm_decrypt(
                plaintext.data(),
                &plaintext_len,
                nullptr,                           // nsec (not used)
                ciphertext_with_nonce.data() + 12, // ciphertext starts after nonce
                ciphertext_with_nonce.size() - 12,
                associated_data.data(),
                associated_data.size(),
                nonce.data(),
                key.data()) != 0)
        {
            return std::unexpected(SigilError::crypto("AES-256-GCM decryption failed (authentication failed)"));
        }

        plaintext.resize(plaintext_len);
        return plaintext;
    }

    AESKey AES256GCM::generate_key()
    {
        AESKey key;
        crypto_aead_aes256gcm_keygen(key.data());
        return key;
    }

    // ============================================================================
    // SHA256 Implementation
    // ============================================================================

    SHA256Hash SHA256::hash(const Bytes &data)
    {
        SHA256Hash output;
        crypto_hash_sha256(output.data(), data.data(), data.size());
        return output;
    }

    SHA256Hash SHA256::hash(const std::string &data)
    {
        SHA256Hash output;
        crypto_hash_sha256(output.data(),
                           reinterpret_cast<const uint8_t *>(data.data()),
                           data.size());
        return output;
    }

    std::string SHA256::to_hex(const SHA256Hash &hash)
    {
        std::string hex;
        hex.reserve(64);
        for (uint8_t byte : hash)
        {
            hex += std::format("{:02x}", byte);
        }
        return hex;
    }

    Result<SHA256Hash> SHA256::from_hex(const std::string &hex)
    {
        if (hex.size() != 64)
        {
            return std::unexpected(SigilError::crypto("Invalid SHA-256 hex length"));
        }

        SHA256Hash hash;
        for (size_t i = 0; i < 32; ++i)
        {
            try
            {
                hash[i] = static_cast<uint8_t>(std::stoi(hex.substr(i * 2, 2), nullptr, 16));
            }
            catch (...)
            {
                return std::unexpected(SigilError::crypto("Invalid hex character"));
            }
        }
        return hash;
    }

    // ============================================================================
    // Argon2 Implementation
    // ============================================================================

    Result<Bytes> Argon2::derive_key(
        const std::string &passphrase,
        const Bytes &salt,
        uint64_t ops_limit,
        size_t mem_limit,
        size_t key_len)
    {
        if (salt.size() < crypto_pwhash_SALTBYTES)
        {
            return std::unexpected(SigilError::crypto(
                std::format("Salt too short, need at least {} bytes", crypto_pwhash_SALTBYTES)));
        }

        Bytes key(key_len);

        if (crypto_pwhash(
                key.data(),
                key_len,
                passphrase.c_str(),
                passphrase.size(),
                salt.data(),
                ops_limit,
                mem_limit,
                crypto_pwhash_ALG_ARGON2ID13) != 0)
        {
            return std::unexpected(SigilError::crypto("Argon2 key derivation failed (out of memory?)"));
        }

        return key;
    }

    // ============================================================================
    // Base64 Implementation
    // ============================================================================

    std::string Base64::encode(const Bytes &data)
    {
        size_t b64_len = sodium_base64_encoded_len(data.size(), sodium_base64_VARIANT_ORIGINAL);
        std::string encoded(b64_len, '\0');

        sodium_bin2base64(
            encoded.data(),
            b64_len,
            data.data(),
            data.size(),
            sodium_base64_VARIANT_ORIGINAL);

        // Remove null terminator
        encoded.resize(std::strlen(encoded.c_str()));
        return encoded;
    }

    Result<Bytes> Base64::decode(const std::string &encoded)
    {
        Bytes decoded(encoded.size()); // Worst case size
        size_t decoded_len;

        if (sodium_base642bin(
                decoded.data(),
                decoded.size(),
                encoded.c_str(),
                encoded.size(),
                nullptr, // ignore characters
                &decoded_len,
                nullptr, // end pointer
                sodium_base64_VARIANT_ORIGINAL) != 0)
        {
            return std::unexpected(SigilError::crypto("Invalid base64 encoding"));
        }

        decoded.resize(decoded_len);
        return decoded;
    }

    std::string Base64::encode_url_safe(const Bytes &data)
    {
        size_t b64_len = sodium_base64_encoded_len(data.size(), sodium_base64_VARIANT_URLSAFE_NO_PADDING);
        std::string encoded(b64_len, '\0');

        sodium_bin2base64(
            encoded.data(),
            b64_len,
            data.data(),
            data.size(),
            sodium_base64_VARIANT_URLSAFE_NO_PADDING);

        encoded.resize(std::strlen(encoded.c_str()));
        return encoded;
    }

    Result<Bytes> Base64::decode_url_safe(const std::string &encoded)
    {
        Bytes decoded(encoded.size());
        size_t decoded_len;

        if (sodium_base642bin(
                decoded.data(),
                decoded.size(),
                encoded.c_str(),
                encoded.size(),
                nullptr,
                &decoded_len,
                nullptr,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0)
        {
            return std::unexpected(SigilError::crypto("Invalid base64url encoding"));
        }

        decoded.resize(decoded_len);
        return decoded;
    }

    // ============================================================================
    // SecureRandom Implementation
    // ============================================================================

    void SecureRandom::fill_bytes(Bytes &buffer)
    {
        randombytes_buf(buffer.data(), buffer.size());
    }

    Bytes SecureRandom::generate_bytes(size_t n)
    {
        Bytes buffer(n);
        randombytes_buf(buffer.data(), n);
        return buffer;
    }

    // ============================================================================
    // CanonSigningKey Implementation (Phase 2B)
    // ============================================================================

    CanonSigningKey CanonSigningKey::generate()
    {
        auto kp_result = Ed25519KeyPair::generate();
        if (!kp_result)
        {
            throw std::runtime_error("Failed to generate signing key");
        }
        return from_keypair(*kp_result);
    }

    Result<CanonSigningKey> CanonSigningKey::load_signing_key_b64(const std::string &b64)
    {
        auto decoded = Base64::decode(b64);
        if (!decoded)
        {
            return std::unexpected(decoded.error());
        }

        if (decoded->size() != 64)
        {
            return std::unexpected(SigilError::validation("Invalid Ed25519 secret key length"));
        }

        std::array<uint8_t, 32> seed;
        std::copy_n(decoded->begin(), 32, seed.begin());

        auto keypair = Ed25519KeyPair::from_seed(seed);
        if (!keypair)
        {
            return std::unexpected(keypair.error());
        }

        return from_keypair(*keypair);
    }

    Result<CanonSigningKey> CanonSigningKey::load_from_file(const std::string &path)
    {
        std::ifstream file(path);
        if (!file)
        {
            return std::unexpected(SigilError(ErrorCode::IOError, std::format("Failed to open key file: {}", path)));
        }

        json j;
        try
        {
            file >> j;
        }
        catch (const json::exception &e)
        {
            return std::unexpected(SigilError(ErrorCode::ParsingError, std::format("Invalid JSON in key file: {}", e.what())));
        }

        if (!j.contains("private_key_b64"))
        {
            return std::unexpected(SigilError(ErrorCode::ValidationError, "Missing private_key_b64 in key file"));
        }

        return load_signing_key_b64(j["private_key_b64"].get<std::string>());
    }

    Result<void> CanonSigningKey::save_to_file(const std::string &path, const std::string &purpose) const
    {
        json j;
        j["public_key_b64"] = public_key_b64();
        j["private_key_b64"] = private_key_b64();
        j["purpose"] = purpose;

        // Get current timestamp in ISO 8601 format
        auto now = std::chrono::system_clock::now();
        auto time_t_now = std::chrono::system_clock::to_time_t(now);
        std::tm tm_utc;
        gmtime_r(&time_t_now, &tm_utc);
        char timestamp[32];
        std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
        j["created_at"] = timestamp;

        // Ensure directory exists
        std::filesystem::path p(path);
        std::filesystem::create_directories(p.parent_path());

        std::ofstream file(path);
        if (!file)
        {
            return std::unexpected(SigilError(ErrorCode::IOError, std::format("Failed to open key file for writing: {}", path)));
        }

        file << j.dump(2);
        return {};
    }

    Result<std::pair<CanonSigningKey, uint32_t>> CanonSigningKey::load_encrypted(
        const std::string &path,
        const AESKey &encryption_key)
    {
        std::ifstream file(path);
        if (!file)
        {
            return std::unexpected(SigilError(ErrorCode::IOError, std::format("Failed to open encrypted key file: {}", path)));
        }

        json j;
        try
        {
            file >> j;
        }
        catch (const json::exception &e)
        {
            return std::unexpected(SigilError(ErrorCode::ParsingError, std::format("Invalid JSON in encrypted key file: {}", e.what())));
        }

        // Validate required fields
        if (!j.contains("encrypted_private_key_b64") || !j.contains("nonce_b64") || !j.contains("key_index"))
        {
            return std::unexpected(SigilError(ErrorCode::ValidationError, "Missing required fields in encrypted key file"));
        }

        // Decode encrypted data
        auto encrypted = Base64::decode(j["encrypted_private_key_b64"].get<std::string>());
        if (!encrypted)
        {
            return std::unexpected(encrypted.error());
        }

        auto nonce = Base64::decode(j["nonce_b64"].get<std::string>());
        if (!nonce)
        {
            return std::unexpected(nonce.error());
        }

        // Decrypt
        auto decrypted = AES256GCM::decrypt(encryption_key, *encrypted, *nonce);
        if (!decrypted)
        {
            return std::unexpected(decrypted.error());
        }

        // Load key from decrypted data
        std::string private_key_b64 = Base64::encode(*decrypted);
        auto key = load_signing_key_b64(private_key_b64);
        if (!key)
        {
            return std::unexpected(key.error());
        }

        uint32_t key_index = j["key_index"].get<uint32_t>();
        return std::make_pair(*key, key_index);
    }

    Result<void> CanonSigningKey::save_encrypted(
        const std::string &path,
        const AESKey &encryption_key,
        uint32_t key_index,
        const std::string &purpose) const
    {
        // Generate nonce for encryption
        auto nonce = SecureRandom::generate_bytes(12);

        // Get private key bytes
        auto private_key_decoded = Base64::decode(private_key_b64());
        if (!private_key_decoded)
        {
            return std::unexpected(private_key_decoded.error());
        }

        // Encrypt private key
        auto encrypted = AES256GCM::encrypt(encryption_key, *private_key_decoded, nonce);
        if (!encrypted)
        {
            return std::unexpected(encrypted.error());
        }

        // Build JSON with metadata
        json j;
        j["version"] = 1;
        j["encrypted_private_key_b64"] = Base64::encode(*encrypted);
        j["public_key_b64"] = public_key_b64();
        j["nonce_b64"] = Base64::encode(nonce);
        j["key_index"] = key_index;
        j["purpose"] = purpose;

        // Get current timestamp in ISO 8601 format
        auto now = std::chrono::system_clock::now();
        auto time_t_now = std::chrono::system_clock::to_time_t(now);
        std::tm tm_utc;
        gmtime_r(&time_t_now, &tm_utc);
        char timestamp[32];
        std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
        j["created_at"] = timestamp;

        // Ensure directory exists
        std::filesystem::path p(path);
        std::filesystem::create_directories(p.parent_path());

        // Write to file
        std::ofstream file(path);
        if (!file)
        {
            return std::unexpected(SigilError(ErrorCode::IOError, std::format("Failed to open encrypted key file for writing: {}", path)));
        }

        file << j.dump(2);
        return {};
    }

    std::string CanonSigningKey::public_key_b64() const
    {
        return Base64::encode(Bytes(keypair.public_key.begin(), keypair.public_key.end()));
    }

    std::string CanonSigningKey::private_key_b64() const
    {
        return Base64::encode(Bytes(keypair.secret_key.begin(), keypair.secret_key.end()));
    }

    std::pair<std::string, std::string> CanonSigningKey::sign_canonical_bytes(const Bytes &canonical_bytes) const
    {
        // Ed25519KeyPair::sign returns std::array<uint8_t, 64> directly
        auto sig_array = keypair.sign(canonical_bytes);

        // Convert to Bytes for Base64 encoding
        Bytes sig_bytes(sig_array.begin(), sig_array.end());
        std::string signature_b64 = Base64::encode(sig_bytes);
        std::string public_key = public_key_b64();
        return {signature_b64, public_key};
    }

    std::pair<std::string, std::string> CanonSigningKey::sign_record(const Bytes &canonical_bytes) const
    {
        return sign_canonical_bytes(canonical_bytes);
    }

    Result<void> CanonSigningKey::verify_signature(const Bytes &canonical_bytes, const std::string &signature_b64) const
    {
        auto signature = Base64::decode(signature_b64);
        if (!signature)
        {
            return std::unexpected(signature.error());
        }

        if (signature->size() != 64)
        {
            return std::unexpected(SigilError(ErrorCode::ValidationError, "Invalid signature length"));
        }

        // Convert to Ed25519Signature array
        Ed25519Signature sig_array;
        std::copy_n(signature->begin(), 64, sig_array.begin());

        // Ed25519KeyPair::verify is static and requires public key
        if (Ed25519KeyPair::verify(canonical_bytes, sig_array, keypair.public_key))
        {
            return {};
        }
        return std::unexpected(SigilError(ErrorCode::CryptoError, "Signature verification failed"));
    }

    CanonSigningKey CanonSigningKey::from_keypair(const Ed25519KeyPair &kp)
    {
        CanonSigningKey key;
        key.keypair = kp;
        return key;
    }

    // ============================================================================
    // KeyStore Implementation (Phase 2B)
    // ============================================================================

    KeyStore::KeyStore() : current_key_index(0) {}

    void KeyStore::add_key(uint32_t key_index, const CanonSigningKey &key)
    {
        keys[key_index] = key;
        if (key_index > current_key_index)
        {
            current_key_index = key_index;
        }
    }

    Result<CanonSigningKey> KeyStore::current_key() const
    {
        if (keys.empty())
        {
            return std::unexpected(SigilError::not_found("KeyStore is empty"));
        }
        return get_key(current_key_index);
    }

    Result<CanonSigningKey> KeyStore::get_key(uint32_t key_index) const
    {
        auto it = keys.find(key_index);
        if (it == keys.end())
        {
            return std::unexpected(SigilError::not_found(std::format("Key index {} not found", key_index)));
        }
        return it->second;
    }

    uint32_t KeyStore::rotate_key()
    {
        uint32_t new_index = current_key_index + 1;
        CanonSigningKey new_key = CanonSigningKey::generate();
        add_key(new_index, new_key);
        return new_index;
    }

    std::vector<uint32_t> KeyStore::key_indices() const
    {
        std::vector<uint32_t> indices;
        indices.reserve(keys.size());
        for (const auto &[idx, _] : keys)
        {
            indices.push_back(idx);
        }
        std::sort(indices.begin(), indices.end());
        return indices;
    }

    Result<KeyStore> KeyStore::load_from_directory(
        const std::string &dir_path,
        const AESKey &encryption_key)
    {
        KeyStore store;

        // Check if directory exists
        if (!std::filesystem::exists(dir_path))
        {
            return std::unexpected(SigilError::not_found(std::format("Key directory not found: {}", dir_path)));
        }

        // Scan for canon_key_*.json files
        for (const auto &entry : std::filesystem::directory_iterator(dir_path))
        {
            if (!entry.is_regular_file())
                continue;

            std::string filename = entry.path().filename().string();
            if (filename.starts_with("canon_key_") && filename.ends_with(".json"))
            {
                auto key_pair = CanonSigningKey::load_encrypted(entry.path().string(), encryption_key);
                if (!key_pair)
                {
                    return std::unexpected(key_pair.error());
                }

                auto [key, key_index] = *key_pair;
                store.add_key(key_index, key);
            }
        }

        if (store.keys.empty())
        {
            return std::unexpected(SigilError::not_found("No encrypted keys found in directory"));
        }

        return store;
    }

    Result<void> KeyStore::save_to_directory(
        const std::string &dir_path,
        const AESKey &encryption_key) const
    {
        // Ensure directory exists
        std::filesystem::create_directories(dir_path);

        for (const auto &[key_index, key] : keys)
        {
            std::string filename = std::format("canon_key_{:04d}.json", key_index);
            std::string filepath = (std::filesystem::path(dir_path) / filename).string();

            auto result = key.save_encrypted(filepath, encryption_key, key_index, "Canon signing key");
            if (!result)
            {
                return result;
            }
        }

        return {};
    }

    // ============================================================================
    // KeyManager Implementation (Phase 2B)
    // ============================================================================

    Result<AESKey> KeyManager::get_encryption_key()
    {
        const char *env_key = std::getenv("CANON_ENCRYPTION_KEY");
        if (env_key == nullptr)
        {
            // For development: use a deterministic dev key (INSECURE - dev only!)
            static const char *DEV_KEY_B64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
            env_key = DEV_KEY_B64;
        }

        auto decoded = Base64::decode(env_key);
        if (!decoded)
        {
            return std::unexpected(decoded.error());
        }

        if (decoded->size() != 32)
        {
            return std::unexpected(SigilError::validation("CANON_ENCRYPTION_KEY must be 32 bytes when base64-decoded"));
        }

        AESKey key;
        std::copy_n(decoded->begin(), 32, key.begin());
        return key;
    }

    std::string KeyManager::get_key_directory()
    {
        const char *env_dir = std::getenv("CANON_KEY_DIR");
        if (env_dir != nullptr)
        {
            return env_dir;
        }
        return "keys/encrypted";
    }

    Result<KeyStore> KeyManager::get_or_create_key_store()
    {
        auto encryption_key = get_encryption_key();
        if (!encryption_key)
        {
            return std::unexpected(encryption_key.error());
        }

        std::string key_dir = get_key_directory();

        // Try to load existing store
        if (std::filesystem::exists(key_dir))
        {
            auto store = KeyStore::load_from_directory(key_dir, *encryption_key);
            if (store)
            {
                return store;
            }
            // If loading failed but directory exists, might be empty or corrupted
        }

        // Try to migrate legacy key
        auto migrated = try_migrate_legacy_key(*encryption_key);
        if (migrated && migrated->has_value())
        {
            return **migrated;
        }

        // Create new store with initial key
        KeyStore store;
        store.rotate_key(); // Creates key index 1

        auto save_result = store.save_to_directory(key_dir, *encryption_key);
        if (!save_result)
        {
            return std::unexpected(save_result.error());
        }

        return store;
    }

    Result<CanonSigningKey> KeyManager::get_or_create_canon_key()
    {
        // Try new key store first
        auto store = get_or_create_key_store();
        if (store)
        {
            return store->current_key();
        }

        // Fallback to legacy path
        std::string legacy_path = default_key_path();
        if (std::filesystem::exists(legacy_path))
        {
            return CanonSigningKey::load_from_file(legacy_path);
        }

        // Create new key and save to legacy location
        CanonSigningKey key = CanonSigningKey::generate();
        auto save_result = key.save_to_file(legacy_path, "Canon signing key");
        if (!save_result)
        {
            return std::unexpected(save_result.error());
        }

        return key;
    }

    Result<uint32_t> KeyManager::rotate_keys(KeyStore &store)
    {
        uint32_t new_index = store.rotate_key();

        auto encryption_key = get_encryption_key();
        if (!encryption_key)
        {
            return std::unexpected(encryption_key.error());
        }

        std::string key_dir = get_key_directory();
        auto save_result = store.save_to_directory(key_dir, *encryption_key);
        if (!save_result)
        {
            return std::unexpected(save_result.error());
        }

        return new_index;
    }

    Result<void> KeyManager::verify_key_pair(const CanonSigningKey &key)
    {
        // Sign test data
        Bytes test_data = {0x01, 0x02, 0x03, 0x04};
        auto [sig, _] = key.sign_canonical_bytes(test_data);

        // Verify signature
        return key.verify_signature(test_data, sig);
    }

    Result<void> KeyManager::verify_key_store(const KeyStore &store)
    {
        auto indices = store.key_indices();
        if (indices.empty())
        {
            return std::unexpected(SigilError::validation("KeyStore is empty"));
        }

        for (uint32_t idx : indices)
        {
            auto key = store.get_key(idx);
            if (!key)
            {
                return std::unexpected(key.error());
            }

            auto verify = verify_key_pair(*key);
            if (!verify)
            {
                return std::unexpected(SigilError::crypto(std::format("Key {} failed verification", idx)));
            }
        }

        return {};
    }

    std::string KeyManager::default_key_path()
    {
        const char *env_path = std::getenv("CANON_LEGACY_KEY_PATH");
        if (env_path != nullptr)
        {
            return env_path;
        }
        return "keys/canon_signing_key.json";
    }

    Result<std::optional<KeyStore>> KeyManager::try_migrate_legacy_key(const AESKey &encryption_key)
    {
        std::string legacy_path = default_key_path();
        if (!std::filesystem::exists(legacy_path))
        {
            return std::optional<KeyStore>{}; // No legacy key to migrate
        }

        auto key = CanonSigningKey::load_from_file(legacy_path);
        if (!key)
        {
            return std::optional<KeyStore>{}; // Failed to load legacy key
        }

        // Create new key store with migrated key as index 1
        KeyStore store;
        store.add_key(1, *key);

        // Save to new location
        std::string key_dir = get_key_directory();
        auto save_result = store.save_to_directory(key_dir, encryption_key);
        if (!save_result)
        {
            return std::unexpected(save_result.error());
        }

        // Backup legacy key
        std::string backup_path = legacy_path + ".legacy_backup";
        std::filesystem::copy_file(legacy_path, backup_path, std::filesystem::copy_options::overwrite_existing);

        return store;
    }

} // namespace sigil::crypto
