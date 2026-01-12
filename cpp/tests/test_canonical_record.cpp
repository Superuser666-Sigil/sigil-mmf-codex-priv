#include <catch2/catch_test_macros.hpp>
#include "sigil/canonical_record.hpp"

using namespace sigil;

TEST_CASE("CanonicalRecord creation", "[canonical_record]")
{
    auto record = CanonicalRecord::create(
        "test_record",
        "rec-001",
        "test-tenant",
        "user",
        nlohmann::json({{"key", "value"}}));

    REQUIRE(record.kind == "test_record");
    REQUIRE(record.id == "rec-001");
    REQUIRE(record.tenant == "test-tenant");
    REQUIRE(record.space == "user");
    REQUIRE(record.schema_version == "1.0");
    REQUIRE(!record.ts.empty());
}

TEST_CASE("CanonicalRecord JSON serialization", "[canonical_record]")
{
    auto record = CanonicalRecord::create(
        "test",
        "id-1",
        "tenant-1",
        "user",
        nlohmann::json({{"data", 123}}));

    auto json = record.to_json();
    REQUIRE(json["kind"] == "test");
    REQUIRE(json["id"] == "id-1");
    REQUIRE(json["payload"]["data"] == 123);

    auto restored = CanonicalRecord::from_json(json);
    REQUIRE(restored.has_value());
    REQUIRE(restored->kind == record.kind);
    REQUIRE(restored->id == record.id);
}

TEST_CASE("CanonicalRecord hash computation", "[canonical_record]")
{
    auto record = CanonicalRecord::create(
        "test",
        "id-1",
        "tenant-1",
        "user",
        nlohmann::json({{"value", 42}}));

    std::string hash1 = record.compute_hash();
    std::string hash2 = record.compute_hash();

    REQUIRE(hash1 == hash2);
    REQUIRE(hash1.length() == 64); // SHA-256 hex
}

TEST_CASE("CanonicalRecord signing and verification", "[canonical_record]")
{
    auto keypair = crypto::Ed25519KeyPair::generate().value();

    auto record = CanonicalRecord::create(
        "test",
        "id-1",
        "tenant-1",
        "user",
        nlohmann::json({{"message", "hello"}}));

    REQUIRE_FALSE(record.is_signed());

    auto sign_result = record.sign(keypair);
    REQUIRE(sign_result.has_value());
    REQUIRE(record.is_signed());
    REQUIRE(record.hash.has_value());
    REQUIRE(record.signature.has_value());
    REQUIRE(record.public_key.has_value());

    bool valid = record.verify_signature();
    REQUIRE(valid);
}

TEST_CASE("CanonicalRecord signature verification fails on tampered data", "[canonical_record]")
{
    auto keypair = crypto::Ed25519KeyPair::generate().value();

    auto record = CanonicalRecord::create(
        "test",
        "id-1",
        "tenant-1",
        "user",
        nlohmann::json({{"value", 100}}));

    record.sign(keypair);
    REQUIRE(record.verify_signature());

    // Tamper with payload
    record.payload["value"] = 999;

    // Signature should now be invalid
    REQUIRE_FALSE(record.verify_signature());
}

TEST_CASE("CanonicalRecord canonical JSON excludes crypto fields", "[canonical_record]")
{
    auto record = CanonicalRecord::create(
        "test",
        "id-1",
        "tenant-1",
        "user",
        nlohmann::json({{"key", "value"}}));

    auto keypair = crypto::Ed25519KeyPair::generate().value();
    record.sign(keypair);

    std::string canonical = record.to_canonical_json();

    // Should not contain signature or public_key
    REQUIRE(canonical.find("signature") == std::string::npos);
    REQUIRE(canonical.find("public_key") == std::string::npos);
    REQUIRE(canonical.find("sig") == std::string::npos);
    REQUIRE(canonical.find("pub_key") == std::string::npos);
    // CRITICAL: Should not contain hash field at all (not even empty)
    REQUIRE(canonical.find("hash") == std::string::npos);
}

TEST_CASE("Link structure", "[canonical_record][link]")
{
    Link link{
        "parent",
        "rec-parent-001"};

    auto json = link.to_json();
    REQUIRE(json["label"] == "parent");
    REQUIRE(json["target"] == "rec-parent-001");

    auto restored = Link::from_json(json);
    REQUIRE(restored.label == link.label);
    REQUIRE(restored.target == link.target);
}

TEST_CASE("WitnessRecord structure", "[canonical_record][witness]")
{
    WitnessRecord witness{
        "witness-001",
        "base64signaturedata",
        "2026-01-11T12:00:00.000Z",
        "trusted-authority"};

    auto json = witness.to_json();
    REQUIRE(json["witness_id"] == "witness-001");
    REQUIRE(json["signature"] == "base64signaturedata");
    REQUIRE(json["timestamp"] == "2026-01-11T12:00:00.000Z");
    REQUIRE(json["authority"] == "trusted-authority");

    auto restored = WitnessRecord::from_json(json);
    REQUIRE(restored.witness_id == witness.witness_id);
    REQUIRE(restored.signature == witness.signature);
    REQUIRE(restored.timestamp == witness.timestamp);
    REQUIRE(restored.authority == witness.authority);
}

TEST_CASE("CanonicalRecord with links", "[canonical_record][link]")
{
    auto record = CanonicalRecord::create(
        "test",
        "child-001",
        "tenant-1",
        "user",
        nlohmann::json({{"data", "test"}}));

    record.links.push_back(Link{"parent", "rec-parent-001"});
    record.links.push_back(Link{"references", "rec-ref-001"});

    auto json = record.to_json();
    REQUIRE(json["links"].is_array());
    REQUIRE(json["links"].size() == 2);
    REQUIRE(json["links"][0]["label"] == "parent");
    REQUIRE(json["links"][1]["label"] == "references");

    auto restored = CanonicalRecord::from_json(json);
    REQUIRE(restored.has_value());
    REQUIRE(restored->links.size() == 2);
    REQUIRE(restored->links[0].label == "parent");
    REQUIRE(restored->links[1].target == "rec-ref-001");
}

TEST_CASE("CanonicalRecord with witnesses", "[canonical_record][witness]")
{
    auto keypair = crypto::Ed25519KeyPair::generate().value();

    auto record = CanonicalRecord::create(
        "test",
        "rec-001",
        "tenant-1",
        "user",
        nlohmann::json({{"message", "important"}}));

    record.sign(keypair);

    // Add witness signatures
    record.add_witness_signature(
        "witness-alice",
        "base64sig1",
        "root-authority");
    record.add_witness_signature(
        "witness-bob",
        "base64sig2",
        "mentor-authority");

    REQUIRE(record.witnesses.size() == 2);
    REQUIRE(record.witnesses[0].witness_id == "witness-alice");
    REQUIRE(record.witnesses[1].authority == "mentor-authority");

    // Verify serialization
    auto json = record.to_json();
    REQUIRE(json["witnesses"].is_array());
    REQUIRE(json["witnesses"].size() == 2);

    auto restored = CanonicalRecord::from_json(json);
    REQUIRE(restored.has_value());
    REQUIRE(restored->witnesses.size() == 2);
    REQUIRE(restored->witnesses[0].witness_id == "witness-alice");
}

TEST_CASE("CanonicalRecord canonical JSON does not include hash field", "[canonical_record][critical]")
{
    auto record = CanonicalRecord::create(
        "test",
        "rec-001",
        "tenant-1",
        "user",
        nlohmann::json({{"data", 123}}));

    auto keypair = crypto::Ed25519KeyPair::generate().value();
    record.sign(keypair);

    // Record now has a hash value
    REQUIRE(record.hash.has_value());

    // But canonical JSON should NOT include it
    std::string canonical = record.to_canonical_json();

    // Parse to verify structure
    auto canonical_json = nlohmann::json::parse(canonical);
    REQUIRE_FALSE(canonical_json.contains("hash"));
    REQUIRE_FALSE(canonical_json.contains("sig"));
    REQUIRE_FALSE(canonical_json.contains("pub_key"));
    REQUIRE_FALSE(canonical_json.contains("witnesses"));

    // But should have the actual data
    REQUIRE(canonical_json.contains("kind"));
    REQUIRE(canonical_json.contains("id"));
    REQUIRE(canonical_json.contains("payload"));
}
