#include "sigil/canonical_record.hpp"
#include "sigil/json_canonicalization.hpp"
#include "sigil/crypto.hpp"
#include "sigil/witness_registry.hpp"
#include <format>
#include <chrono>

namespace sigil
{

    using Json = nlohmann::json;
    using Bytes = crypto::Bytes;

    // ========== Link Implementation ==========

    Json Link::to_json() const
    {
        return Json{
            {"label", label},
            {"target", target}};
    }

    Link Link::from_json(const Json &j)
    {
        return Link{
            j.at("label").get<std::string>(),
            j.at("target").get<std::string>()};
    }

    // ========== WitnessRecord Implementation ==========

    Json WitnessRecord::to_json() const
    {
        return Json{
            {"witness_id", witness_id},
            {"signature", signature},
            {"timestamp", timestamp},
            {"authority", authority}};
    }

    WitnessRecord WitnessRecord::from_json(const Json &j)
    {
        return WitnessRecord{
            j.at("witness_id").get<std::string>(),
            j.at("signature").get<std::string>(),
            j.at("timestamp").get<std::string>(),
            j.at("authority").get<std::string>()};
    }

    // ========== CanonicalRecord Implementation ==========

    CanonicalRecord CanonicalRecord::create(
        const std::string &kind,
        const std::string &id,
        const std::string &tenant,
        const std::string &space,
        const Json &payload)
    {
        CanonicalRecord record;
        record.kind = kind;
        record.schema_version = "1.0";
        record.id = id;
        record.tenant = tenant;
        record.space = space;
        record.payload = payload;

        // Generate ISO 8601 timestamp
        auto now = std::chrono::system_clock::now();
        auto time_t_now = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      now.time_since_epoch()) %
                  1000;

        std::tm tm_buf;
        gmtime_r(&time_t_now, &tm_buf);
        record.ts = std::format("{:04d}-{:02d}-{:02d}T{:02d}:{:02d}:{:02d}.{:03d}Z",
                                tm_buf.tm_year + 1900,
                                tm_buf.tm_mon + 1,
                                tm_buf.tm_mday,
                                tm_buf.tm_hour,
                                tm_buf.tm_min,
                                tm_buf.tm_sec,
                                static_cast<int>(ms.count()));

        return record;
    }

    Result<CanonicalRecord> CanonicalRecord::new_signed(
        const std::string &kind,
        const std::string &id,
        const std::string &tenant,
        const std::string &space,
        const Json &payload,
        const std::optional<std::string> &prev)
    {
        // Get signing key from KeyManager
        auto key_result = crypto::KeyManager::get_or_create_canon_key();
        if (!key_result)
        {
            return std::unexpected(key_result.error());
        }
        auto key = *key_result;

        // Create record with unsigned data
        CanonicalRecord rec = create(kind, id, tenant, space, payload);

        // Set previous hash if provided
        if (prev)
        {
            rec.previous_hash = *prev;
        }

        // Compute canonical JSON (excludes hash field)
        Json canonical = rec.to_canonical_json();
        // Use RFC 8785 canonicalization (matches Rust canonicalize.rs)
        std::string canonical_str = sigil::json::RFC8785Canonicalizer::canonicalize(canonical);
        Bytes canonical_bytes(canonical_str.begin(), canonical_str.end());

        // Compute hash (SHA256::hash returns SHA256Hash directly, not Result)
        auto hash_array = crypto::SHA256::hash(canonical_bytes);
        rec.hash = crypto::Base64::encode(Bytes(hash_array.begin(), hash_array.end()));

        // Sign canonical bytes (hash is NOT in signature, matches Rust)
        auto [sig, pub_key] = key.sign_canonical_bytes(canonical_bytes);
        rec.signature = sig;
        rec.public_key = pub_key;

        return rec;
    }

    Json CanonicalRecord::to_json() const
    {
        Json j = {
            {"kind", kind},
            {"schema_version", schema_version},
            {"id", id},
            {"tenant", tenant},
            {"ts", ts},
            {"space", space},
            {"payload", payload}};

        // Add links if present
        if (!links.empty())
        {
            Json links_array = Json::array();
            for (const auto &link : links)
            {
                links_array.push_back(link.to_json());
            }
            j["links"] = links_array;
        }

        if (hash)
            j["hash"] = *hash;
        if (signature)
            j["sig"] = *signature; // Match Rust field name
        if (public_key)
            j["pub_key"] = *public_key; // Match Rust field name
        if (previous_hash)
            j["prev"] = *previous_hash; // Match Rust field name

        // Add witnesses if present
        if (!witnesses.empty())
        {
            Json witnesses_array = Json::array();
            for (const auto &witness : witnesses)
            {
                witnesses_array.push_back(witness.to_json());
            }
            j["witnesses"] = witnesses_array;
        }

        return j;
    }

    Result<CanonicalRecord> CanonicalRecord::from_json(const Json &j)
    {
        try
        {
            CanonicalRecord record;

            record.kind = j.at("kind").get<std::string>();
            record.schema_version = j.at("schema_version").get<std::string>();
            record.id = j.at("id").get<std::string>();
            record.tenant = j.at("tenant").get<std::string>();
            record.ts = j.at("ts").get<std::string>();
            record.space = j.at("space").get<std::string>();
            record.payload = j.at("payload");

            if (j.contains("hash"))
            {
                record.hash = j["hash"].get<std::string>();
            }
            if (j.contains("signature") || j.contains("sig"))
            {
                record.signature = j.contains("sig") ? j["sig"].get<std::string>() : j["signature"].get<std::string>();
            }
            if (j.contains("public_key") || j.contains("pub_key"))
            {
                record.public_key = j.contains("pub_key") ? j["pub_key"].get<std::string>() : j["public_key"].get<std::string>();
            }

            // Parse optional fields - support both naming conventions
            if (j.contains("previous_hash"))
            {
                record.previous_hash = j["previous_hash"].get<std::string>();
            }
            else if (j.contains("prev"))
            {
                record.previous_hash = j["prev"].get<std::string>();
            }

            // Parse links
            if (j.contains("links") && j["links"].is_array())
            {
                for (const auto &link_json : j["links"])
                {
                    record.links.push_back(Link::from_json(link_json));
                }
            }

            // Parse witnesses
            if (j.contains("witnesses") && j["witnesses"].is_array())
            {
                for (const auto &witness_json : j["witnesses"])
                {
                    record.witnesses.push_back(WitnessRecord::from_json(witness_json));
                }
            }

            return record;
        }
        catch (const Json::exception &e)
        {
            return std::unexpected(SigilError::invalid_input(
                std::format("Failed to parse CanonicalRecord: {}", e.what())));
        }
    }

    std::string CanonicalRecord::to_canonical_json() const
    {
        // Create JSON without cryptographic fields
        // This matches Rust's canonicalize_record() behavior
        Json j = {
            {"kind", kind},
            {"schema_version", schema_version},
            {"id", id},
            {"tenant", tenant},
            {"ts", ts},
            {"space", space},
            {"payload", payload}};

        // Add links if present
        if (!links.empty())
        {
            Json links_array = Json::array();
            for (const auto &link : links)
            {
                links_array.push_back(link.to_json());
            }
            j["links"] = links_array;
        }

        // Include previous_hash if present (part of the chain)
        // Use "prev" to match Rust
        if (previous_hash)
        {
            j["prev"] = *previous_hash;
        }

        // CRITICAL: Do NOT include hash field (matches Rust map.remove("hash"))
        // Do NOT include sig, pub_key, or witnesses

        // Canonicalize using RFC 8785
        return json::RFC8785Canonicalizer::canonicalize(j);
    }

    std::string CanonicalRecord::compute_hash() const
    {
        auto canonical = to_canonical_json();
        auto hash_bytes = crypto::SHA256::hash(canonical);
        return crypto::SHA256::to_hex(hash_bytes);
    }

    Result<void> CanonicalRecord::sign(const crypto::Ed25519KeyPair &keypair)
    {
        // Compute hash if not already present
        if (!hash)
        {
            hash = compute_hash();
        }

        // Get canonical JSON bytes for signing
        auto canonical = to_canonical_json();
        crypto::Bytes message(canonical.begin(), canonical.end());

        // Sign
        auto sig = keypair.sign(message);

        // Store signature and public key as base64
        signature = crypto::Base64::encode(
            crypto::Bytes(sig.begin(), sig.end()));
        public_key = crypto::Base64::encode(
            crypto::Bytes(keypair.public_key.begin(), keypair.public_key.end()));

        return {};
    }

    bool CanonicalRecord::verify_signature() const
    {
        if (!signature || !public_key)
        {
            return false;
        }

        // Decode signature and public key
        auto sig_result = crypto::Base64::decode(*signature);
        if (!sig_result || sig_result->size() != 64)
        {
            return false;
        }

        auto pubkey_result = crypto::Base64::decode(*public_key);
        if (!pubkey_result || pubkey_result->size() != 32)
        {
            return false;
        }

        // Convert to fixed-size arrays
        crypto::Ed25519Signature sig;
        crypto::Ed25519PublicKey pubkey;
        std::copy(sig_result->begin(), sig_result->end(), sig.begin());
        std::copy(pubkey_result->begin(), pubkey_result->end(), pubkey.begin());

        // Get canonical JSON for verification
        auto canonical = to_canonical_json();
        crypto::Bytes message(canonical.begin(), canonical.end());

        return crypto::Ed25519KeyPair::verify(message, sig, pubkey);
    }

    void CanonicalRecord::add_witness_signature(const WitnessRecord &witness)
    {
        witnesses.push_back(witness);
    }

    void CanonicalRecord::add_witness_signature(
        const std::string &witness_id,
        const std::string &signature,
        const std::string &authority)
    {
        // Generate ISO 8601 timestamp
        auto now = std::chrono::system_clock::now();
        auto time_t_now = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      now.time_since_epoch()) %
                  1000;

        std::tm tm_buf;
        gmtime_r(&time_t_now, &tm_buf);
        auto timestamp = std::format("{:04d}-{:02d}-{:02d}T{:02d}:{:02d}:{:02d}.{:03d}Z",
                                     tm_buf.tm_year + 1900,
                                     tm_buf.tm_mon + 1,
                                     tm_buf.tm_mday,
                                     tm_buf.tm_hour,
                                     tm_buf.tm_min,
                                     tm_buf.tm_sec,
                                     static_cast<int>(ms.count()));

        witnesses.push_back(WitnessRecord{
            witness_id,
            signature,
            timestamp,
            authority});
    }

    bool CanonicalRecord::verify_witness_signatures() const
    {
        // Without a registry, we cannot validate witness signatures. Enforce failure
        // when witness entries exist to prevent silently trusting unverified signatures.
        return witnesses.empty();
    }

    Result<bool> CanonicalRecord::verify_witness_signatures_with_registry(const WitnessRegistry &registry) const
    {
        if (witnesses.empty())
            return true;

        auto canonical = to_canonical_json();
        crypto::Bytes message(canonical.begin(), canonical.end());

        for (const auto &w : witnesses)
        {
            auto res = registry.validate_witness_signature(w.witness_id, message, w.signature);
            if (!res)
                return std::unexpected(res.error());
            if (!*res)
                return false;
        }
        return true;
    }

} // namespace sigil
