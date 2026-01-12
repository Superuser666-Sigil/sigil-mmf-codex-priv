#pragma once

#include "types.hpp"
#include "crypto.hpp"
#include <nlohmann/json.hpp>
#include <string>
#include <optional>
#include <chrono>
#include <vector>

namespace sigil
{

    class WitnessRegistry;

    /**
     * Simple relation between two records.
     * Maps to Link in canonical_record.rs
     */
    struct Link
    {
        std::string label;  // Relationship type (e.g., "parent", "references")
        std::string target; // Target record ID

        nlohmann::json to_json() const;
        static Link from_json(const nlohmann::json &j);
    };

    /**
     * External witness signature attached to a record.
     * Maps to WitnessRecord in canonical_record.rs
     */
    struct WitnessRecord
    {
        std::string witness_id; // Witness identifier
        std::string signature;  // Ed25519 signature (base64)
        std::string timestamp;  // ISO 8601 timestamp
        std::string authority;  // Authority/role of witness

        nlohmann::json to_json() const;
        static WitnessRecord from_json(const nlohmann::json &j);
    };

    /**
     * Canonical Record structure
     * Maps to CanonicalRecord in canonical_record.rs
     *
     * All fields must match Rust layout for cross-compatibility
     */
    struct CanonicalRecord
    {
        std::string kind;           // Record type
        std::string schema_version; // Schema version
        std::string id;             // Unique identifier
        std::string tenant;         // Tenant/namespace
        std::string ts;             // ISO 8601 timestamp
        std::string space;          // Space (user/system)
        nlohmann::json payload;     // Arbitrary JSON payload
        std::vector<Link> links;    // Relationships to other records

        // Cryptographic fields
        std::optional<std::string> hash;          // SHA-256 hash (hex)
        std::optional<std::string> signature;     // Ed25519 signature (base64)
        std::optional<std::string> public_key;    // Ed25519 public key (base64)
        std::optional<std::string> previous_hash; // Link to previous record (merkle chain)
        std::vector<WitnessRecord> witnesses;     // External witness signatures

        /**
         * Create a new unsigned canonical record
         */
        static CanonicalRecord create(
            const std::string &kind,
            const std::string &id,
            const std::string &tenant,
            const std::string &space,
            const nlohmann::json &payload);

        /**
         * Create a new signed canonical record with proper signing flow
         * Requires KeyStore implementation (Phase 2B)
         */
        static Result<CanonicalRecord> new_signed(
            const std::string &kind,
            const std::string &id,
            const std::string &tenant,
            const std::string &space,
            const nlohmann::json &payload,
            const std::optional<std::string> &previous_hash);

        /**
         * Construct from FrozenChain
         * Requires audit_chain structures (Phase 2)
         */
        // static Result<CanonicalRecord> from_frozen_chain(
        //     const FrozenChain& chain,
        //     const std::string& tenant,
        //     const std::string& space,
        //     const std::optional<std::string>& previous_hash);

        /**
         * Construct from ReasoningChain
         * Requires audit_chain structures (Phase 2)
         */
        // static Result<CanonicalRecord> from_reasoning_chain(
        //     const ReasoningChain& chain,
        //     const std::string& tenant,
        //     const std::string& space,
        //     const std::optional<std::string>& previous_hash);

        /**
         * Construct from TrustedKnowledgeEntry
         * Requires trusted_knowledge structures (Phase 3)
         */
        // static Result<CanonicalRecord> from_trusted_entry(
        //     const TrustedKnowledgeEntry& entry,
        //     const std::string& tenant,
        //     const std::string& space,
        //     uint32_t schema_version);

        /**
         * Convert to JSON (all fields)
         */
        nlohmann::json to_json() const;

        /**
         * Parse from JSON
         */
        static Result<CanonicalRecord> from_json(const nlohmann::json &j);

        /**
         * Serialize to RFC 8785 canonical JSON (for hashing/signing)
         * Excludes hash, signature, and witness_signatures fields
         */
        std::string to_canonical_json() const;

        /**
         * Compute content hash (SHA-256 of canonical JSON)
         * Does NOT include hash, signature, or witness_signatures in computation
         */
        std::string compute_hash() const;

        /**
         * Sign the record with given keypair
         * Computes hash if not already present, then signs canonical JSON
         */
        Result<void> sign(const crypto::Ed25519KeyPair &keypair);

        /**
         * Verify signature against public key
         */
        bool verify_signature() const;

        /**
         * Add a witness signature with full metadata
         */
        void add_witness_signature(const WitnessRecord &witness);

        /**
         * Add a witness signature from raw components
         */
        void add_witness_signature(
            const std::string &witness_id,
            const std::string &signature,
            const std::string &authority);

        /**
         * Verify all witness signatures.
         * Without a registry, this returns true only if there are no witnesses.
         * Use verify_witness_signatures_with_registry for actual verification.
         */
        bool verify_witness_signatures() const;

        /** Verify witnesses using a registry for public key lookup */
        Result<bool> verify_witness_signatures_with_registry(const WitnessRegistry &registry) const;

        /**
         * Check if record is signed
         */
        bool is_signed() const
        {
            return signature.has_value() && public_key.has_value();
        }
    };

} // namespace sigil
