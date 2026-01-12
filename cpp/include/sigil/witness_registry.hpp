#pragma once

#include "canon_store.hpp"
#include "canonical_record.hpp"
#include "crypto.hpp"
#include "types.hpp"
#include <chrono>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace sigil
{

    struct TrustedWitness
    {
        std::string witness_id;
        std::string public_key; // base64 Ed25519 public key
        std::string authority;
        std::string added_at; // ISO 8601 timestamp
        std::string description;
        bool is_active{true};

        static TrustedWitness create(
            std::string witness_id,
            std::string public_key,
            std::string authority,
            std::string description);
    };

    class WitnessRegistry
    {
    public:
        explicit WitnessRegistry(std::shared_ptr<CanonStore> canon_store);

        Result<void> add_witness(
            std::string witness_id,
            std::string public_key,
            std::string authority,
            std::string description,
            const LOA &requester_loa);

        Result<void> remove_witness(
            std::string_view witness_id,
            const LOA &requester_loa);

        std::optional<TrustedWitness> get_witness(std::string_view witness_id) const;

        Result<std::vector<TrustedWitness>> list_active_witnesses() const;

        Result<bool> is_trusted_witness(std::string_view witness_id) const;

        Result<bool> validate_witness_signature(
            std::string_view witness_id,
            const std::vector<uint8_t> &message,
            std::string_view signature_base64) const;

        Result<void> reload_from_canon();

    private:
        Result<void> store_witness_in_canon(const TrustedWitness &witness);

        std::shared_ptr<CanonStore> canon_store_;
        mutable std::shared_mutex mutex_;
        std::unordered_map<std::string, TrustedWitness> cache_;
    };

} // namespace sigil
