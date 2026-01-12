#include "sigil/witness_registry.hpp"
#include <nlohmann/json.hpp>
#include <format>
#include <chrono>
#include <algorithm>
#include <optional>
#include <mutex>
#include <shared_mutex>

namespace sigil
{

    namespace
    {
        std::string now_iso8601()
        {
            using clock = std::chrono::system_clock;
            auto now = clock::now();
            auto time_t_now = clock::to_time_t(now);
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

            std::tm tm_buf;
            gmtime_r(&time_t_now, &tm_buf);
            return std::format("{:04d}-{:02d}-{:02d}T{:02d}:{:02d}:{:02d}.{:03d}Z",
                               tm_buf.tm_year + 1900,
                               tm_buf.tm_mon + 1,
                               tm_buf.tm_mday,
                               tm_buf.tm_hour,
                               tm_buf.tm_min,
                               tm_buf.tm_sec,
                               static_cast<int>(ms.count()));
        }

        Result<void> require_root(const LOA &requester)
        {
            if (requester != LOA::Root)
            {
                return std::unexpected(SigilError::loa_denied("Root LOA required for witness registry mutations"));
            }
            return {};
        }
    } // namespace

    TrustedWitness TrustedWitness::create(
        std::string witness_id,
        std::string public_key,
        std::string authority,
        std::string description)
    {
        return TrustedWitness{
            std::move(witness_id),
            std::move(public_key),
            std::move(authority),
            now_iso8601(),
            std::move(description),
            true};
    }

    WitnessRegistry::WitnessRegistry(std::shared_ptr<CanonStore> canon_store)
        : canon_store_(std::move(canon_store))
    {
        // Best-effort load; ignore errors if backend not ready
        auto _ = reload_from_canon();
    }

    Result<void> WitnessRegistry::add_witness(
        std::string witness_id,
        std::string public_key,
        std::string authority,
        std::string description,
        const LOA &requester_loa)
    {
        if (auto auth = require_root(requester_loa); !auth)
            return auth;

        // Basic base64 validation of public key
        auto decoded = crypto::Base64::decode(public_key);
        if (!decoded)
        {
            return std::unexpected(decoded.error());
        }
        if (decoded->size() != 32)
        {
            return std::unexpected(SigilError::validation("Invalid public key length (expected 32 bytes)"));
        }

        // Ensure unique ID
        {
            std::shared_lock lock(mutex_);
            if (cache_.contains(witness_id))
            {
                return std::unexpected(SigilError::invalid_input("Witness already exists"));
            }
        }

        TrustedWitness witness = TrustedWitness::create(
            std::move(witness_id),
            std::move(public_key),
            std::move(authority),
            std::move(description));

        if (auto res = store_witness_in_canon(witness); !res)
            return res;

        {
            std::unique_lock lock(mutex_);
            cache_.emplace(witness.witness_id, std::move(witness));
        }

        return {};
    }

    Result<void> WitnessRegistry::remove_witness(
        std::string_view witness_id,
        const LOA &requester_loa)
    {
        if (auto auth = require_root(requester_loa); !auth)
            return auth;

        TrustedWitness witness;
        {
            std::shared_lock lock(mutex_);
            auto it = cache_.find(std::string(witness_id));
            if (it == cache_.end())
            {
                return std::unexpected(SigilError::not_found("witness not found"));
            }
            witness = it->second;
        }

        witness.is_active = false;
        if (auto res = store_witness_in_canon(witness); !res)
            return res;

        {
            std::unique_lock lock(mutex_);
            cache_[std::string(witness_id)] = witness;
        }

        return {};
    }

    std::optional<TrustedWitness> WitnessRegistry::get_witness(std::string_view witness_id) const
    {
        std::shared_lock lock(mutex_);
        auto it = cache_.find(std::string(witness_id));
        if (it == cache_.end())
            return std::nullopt;
        return it->second;
    }

    Result<std::vector<TrustedWitness>> WitnessRegistry::list_active_witnesses() const
    {
        std::vector<TrustedWitness> out;
        std::shared_lock lock(mutex_);
        for (const auto &[_, w] : cache_)
        {
            if (w.is_active)
                out.push_back(w);
        }
        return out;
    }

    Result<bool> WitnessRegistry::is_trusted_witness(std::string_view witness_id) const
    {
        std::shared_lock lock(mutex_);
        auto it = cache_.find(std::string(witness_id));
        if (it == cache_.end())
            return false;
        return it->second.is_active;
    }

    Result<bool> WitnessRegistry::validate_witness_signature(
        std::string_view witness_id,
        const std::vector<uint8_t> &message,
        std::string_view signature_base64) const
    {
        auto witness = get_witness(witness_id);
        if (!witness || !witness->is_active)
            return false;

        if (signature_base64.empty())
            return false;

        auto pub_key_bytes = crypto::Base64::decode(witness->public_key);
        if (!pub_key_bytes)
            return std::unexpected(pub_key_bytes.error());
        if (pub_key_bytes->size() != 32)
            return std::unexpected(SigilError::crypto("Invalid public key length (expected 32 bytes)"));

        auto sig_bytes = crypto::Base64::decode(std::string(signature_base64));
        if (!sig_bytes)
            return std::unexpected(sig_bytes.error());
        if (sig_bytes->size() != 64)
            return std::unexpected(SigilError::crypto("Invalid signature length (expected 64 bytes)"));

        crypto::Ed25519PublicKey pub{};
        std::copy(pub_key_bytes->begin(), pub_key_bytes->end(), pub.begin());

        crypto::Ed25519Signature sig{};
        std::copy(sig_bytes->begin(), sig_bytes->end(), sig.begin());

        bool ok = crypto::Ed25519KeyPair::verify(message, sig, pub);
        return ok;
    }

    Result<void> WitnessRegistry::reload_from_canon()
    {
        if (!canon_store_)
        {
            return {};
        }

        auto records = canon_store_->list_records(std::optional<std::string>("trusted_witness"), LOA::Root);

        std::unordered_map<std::string, TrustedWitness> next;
        for (const auto &rec : records)
        {
            try
            {
                TrustedWitness w;
                w.witness_id = rec.payload.at("witness_id").get<std::string>();
                w.public_key = rec.payload.at("public_key").get<std::string>();
                w.authority = rec.payload.value("authority", "");
                w.added_at = rec.payload.value("added_at", now_iso8601());
                w.description = rec.payload.value("description", "");
                w.is_active = rec.payload.value("is_active", true);
                next.emplace(w.witness_id, std::move(w));
            }
            catch (const std::exception &)
            {
                // Skip malformed record; continue best-effort
            }
        }

        {
            std::unique_lock lock(mutex_);
            cache_ = std::move(next);
        }
        return {};
    }

    Result<void> WitnessRegistry::store_witness_in_canon(const TrustedWitness &witness)
    {
        if (!canon_store_)
        {
            return {};
        }

        nlohmann::json payload = {
            {"witness_id", witness.witness_id},
            {"public_key", witness.public_key},
            {"authority", witness.authority},
            {"added_at", witness.added_at},
            {"description", witness.description},
            {"is_active", witness.is_active}};

        auto record_result = CanonicalRecord::new_signed(
            "trusted_witness",
            std::format("witness:{}", witness.witness_id),
            "system",
            "system",
            payload,
            std::nullopt);

        if (!record_result)
        {
            return std::unexpected(record_result.error());
        }

        return canon_store_->add_record(*record_result, LOA::Root, true);
    }

} // namespace sigil
