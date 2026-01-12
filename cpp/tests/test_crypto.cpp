#include <catch2/catch_test_macros.hpp>
#include "sigil/crypto.hpp"
#include <string>

using namespace sigil::crypto;

TEST_CASE("Ed25519 key generation", "[crypto]")
{
    auto keypair_result = Ed25519KeyPair::generate();
    REQUIRE(keypair_result.has_value());

    auto keypair = keypair_result.value();
    REQUIRE(keypair.public_key.size() == 32);
    REQUIRE(keypair.secret_key.size() == 64);
}

TEST_CASE("Ed25519 signing and verification", "[crypto]")
{
    auto keypair = Ed25519KeyPair::generate().value();

    std::string message = "Hello, Sigil!";
    Bytes message_bytes(message.begin(), message.end());

    auto signature = keypair.sign(message_bytes);
    REQUIRE(signature.size() == 64);

    bool valid = Ed25519KeyPair::verify(message_bytes, signature, keypair.public_key);
    REQUIRE(valid);

    // Test with modified message
    message_bytes[0] ^= 0x01;
    bool invalid = Ed25519KeyPair::verify(message_bytes, signature, keypair.public_key);
    REQUIRE_FALSE(invalid);
}

TEST_CASE("Ed25519 JSON serialization", "[crypto]")
{
    auto keypair = Ed25519KeyPair::generate().value();

    std::string json = keypair.to_json();
    REQUIRE(!json.empty());

    auto restored = Ed25519KeyPair::from_json(json);
    REQUIRE(restored.has_value());
    REQUIRE(restored->public_key == keypair.public_key);
    REQUIRE(restored->secret_key == keypair.secret_key);
}

TEST_CASE("AES-256-GCM encryption/decryption", "[crypto]")
{
    auto key = AES256GCM::generate_key();

    std::string plaintext = "Sensitive data for encryption";
    Bytes plaintext_bytes(plaintext.begin(), plaintext.end());

    auto encrypted = AES256GCM::encrypt(key, plaintext_bytes);
    REQUIRE(encrypted.has_value());
    REQUIRE(encrypted->size() > plaintext_bytes.size()); // Should include nonce + tag

    auto decrypted = AES256GCM::decrypt(key, *encrypted);
    REQUIRE(decrypted.has_value());
    REQUIRE(*decrypted == plaintext_bytes);
}

TEST_CASE("SHA-256 hashing", "[crypto]")
{
    std::string data = "test data";
    auto hash = SHA256::hash(data);
    REQUIRE(hash.size() == 32);

    std::string hex = SHA256::to_hex(hash);
    REQUIRE(hex.length() == 64);

    auto restored = SHA256::from_hex(hex);
    REQUIRE(restored.has_value());
    REQUIRE(*restored == hash);
}

TEST_CASE("Base64 encoding/decoding", "[crypto]")
{
    Bytes data = {0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE};

    std::string encoded = Base64::encode(data);
    REQUIRE(!encoded.empty());

    auto decoded = Base64::decode(encoded);
    REQUIRE(decoded.has_value());
    REQUIRE(*decoded == data);
}

TEST_CASE("Secure random generation", "[crypto]")
{
    auto bytes1 = SecureRandom::generate_bytes(32);
    auto bytes2 = SecureRandom::generate_bytes(32);

    REQUIRE(bytes1.size() == 32);
    REQUIRE(bytes2.size() == 32);
    REQUIRE(bytes1 != bytes2); // Should be different with high probability
}
