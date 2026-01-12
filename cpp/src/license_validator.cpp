#include "sigil/license_validator.hpp"
#include "sigil/crypto.hpp"
#include "sigil/json_canonicalization.hpp"
#include <fstream>
#include <sstream>
#include <chrono>
#include <cstdio>
#include <format>

#ifdef SIGIL_HAVE_TOMLPP
#include <toml++/toml.h>
#endif

namespace sigil
{

    Result<LicenseDocument> LicenseValidator::load(const std::string &path)
    {
        std::ifstream file(path);
        if (!file.is_open())
        {
            return std::unexpected(SigilError::license("Failed to open license file: " + path));
        }
        std::stringstream buffer;
        buffer << file.rdbuf();
        return parse_toml(buffer.str());
    }

    Result<LicenseDocument> LicenseValidator::parse_toml(const std::string &content)
    {
#ifndef SIGIL_HAVE_TOMLPP
        return std::unexpected(SigilError::config("toml++ not available; cannot parse license"));
#else
        try
        {
            auto tbl = toml::parse(content);
            LicenseDocument doc;
            doc.product = tbl["product"].value_or(std::string("unknown"));
            doc.holder = tbl["holder"].value_or(std::string("unknown"));
            doc.expires_at = tbl["expires_at"].value_or(std::string("9999-12-31T00:00:00Z"));
            doc.public_key_b64 = tbl["public_key"].value_or(std::string());
            doc.signature_b64 = tbl["signature"].value_or(std::string());

            auto to_json = [&](const toml::node &node, const auto &self) -> nlohmann::json {
                if (auto v = node.as_string())
                    return v->get();
                if (auto v = node.as_integer())
                    return v->get();
                if (auto v = node.as_floating_point())
                    return v->get();
                if (auto v = node.as_boolean())
                    return v->get();
                if (auto arr = node.as_array())
                {
                    nlohmann::json j = nlohmann::json::array();
                    for (const auto &elem : *arr)
                        j.push_back(self(elem, self));
                    return j;
                }
                if (auto tbl = node.as_table())
                {
                    nlohmann::json j = nlohmann::json::object();
                    for (auto &&[k, v] : *tbl)
                    {
                        std::string key_str(k.str());
                        j[key_str] = self(v, self);
                    }
                    return j;
                }
                return nullptr;
            };

            nlohmann::json claims_json = nlohmann::json::object();
            for (auto &&[key, val] : tbl)
            {
                if (key == "product" || key == "holder" || key == "expires_at" || key == "public_key" || key == "signature")
                    continue;
                std::string key_str(key.str());
                claims_json[key_str] = to_json(val, to_json);
            }
            doc.claims = claims_json;
            return doc;
        }
        catch (const std::exception &e)
        {
            return std::unexpected(SigilError::license(std::string("License parse error: ") + e.what()));
        }
#endif
    }

    Result<void> LicenseValidator::validate(const LicenseDocument &doc)
    {
        if (doc.public_key_b64.empty() || doc.signature_b64.empty())
        {
            return std::unexpected(SigilError::license("License missing public key or signature"));
        }

        if (is_expired(doc.expires_at))
        {
            return std::unexpected(SigilError::license("License expired"));
        }

        // Canonicalize payload (without signature)
        nlohmann::json payload = {
            {"product", doc.product},
            {"holder", doc.holder},
            {"expires_at", doc.expires_at},
            {"public_key", doc.public_key_b64},
            {"claims", doc.claims}};
        std::string canonical = json::RFC8785Canonicalizer::canonicalize(payload);
        crypto::Bytes message(canonical.begin(), canonical.end());

        auto sig_bytes = crypto::Base64::decode(doc.signature_b64);
        if (!sig_bytes || sig_bytes->size() != 64)
        {
            return std::unexpected(SigilError::license("Invalid signature encoding"));
        }
        auto pub_bytes = crypto::Base64::decode(doc.public_key_b64);
        if (!pub_bytes || pub_bytes->size() != 32)
        {
            return std::unexpected(SigilError::license("Invalid public key encoding"));
        }

        crypto::Ed25519Signature sig{};
        std::copy(sig_bytes->begin(), sig_bytes->end(), sig.begin());
        crypto::Ed25519PublicKey pub{};
        std::copy(pub_bytes->begin(), pub_bytes->end(), pub.begin());

        bool ok = crypto::Ed25519KeyPair::verify(message, sig, pub);
        if (!ok)
        {
            return std::unexpected(SigilError::license("License signature verification failed"));
        }
        return {};
    }

    bool LicenseValidator::is_expired(const std::string &iso_ts)
    {
        // Simplified check: lexical comparison against now in RFC3339 format
        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);
        std::tm tm_buf;
        gmtime_r(&t, &tm_buf);
        auto now_str = std::format("{:04d}-{:02d}-{:02d}T{:02d}:{:02d}:{:02d}Z",
                                   tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
                                   tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec);
        return iso_ts < now_str;
    }

} // namespace sigil
