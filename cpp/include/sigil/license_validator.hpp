#pragma once

#include "types.hpp"
#include <nlohmann/json.hpp>
#include <string>
#include <optional>

namespace sigil
{
    struct LicenseDocument
    {
        std::string product;
        std::string holder;
        std::string expires_at; // ISO 8601
        std::string public_key_b64;
        std::string signature_b64;
        nlohmann::json claims; // remaining fields
    };

    class LicenseValidator
    {
    public:
        /** Load a license TOML file */
        static Result<LicenseDocument> load(const std::string &path);

        /** Validate signature and expiry */
        static Result<void> validate(const LicenseDocument &doc);

        /** Parse license data from TOML content */
        static Result<LicenseDocument> parse_toml(const std::string &content);

    private:
        static bool is_expired(const std::string &iso_ts);
    };
}
