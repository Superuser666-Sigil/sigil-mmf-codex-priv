#pragma once

#include "types.hpp"
#include <nlohmann/json.hpp>
#include <string>

namespace sigil::json
{

    /**
     * RFC 8785 JSON Canonicalization Scheme (JCS)
     *
     * Implements deterministic JSON serialization for cryptographic operations.
     * This MUST produce byte-identical output to the Rust implementation in canonicalize.rs
     * for signature compatibility with existing records.
     *
     * Key requirements:
     * - Unicode normalization (NFC)
     * - Lexicographic key sorting
     * - No insignificant whitespace
     * - Escape sequences for control characters
     * - IEEE 754 number serialization
     */
    class RFC8785Canonicalizer
    {
    public:
        /**
         * Canonicalize a JSON value to RFC 8785 format
         * @param value JSON value to canonicalize
         * @return Canonical JSON string
         */
        static std::string canonicalize(const nlohmann::json &value);

        /**
         * Parse JSON string and canonicalize
         * @param json_str Input JSON string
         * @return Canonical JSON string or error
         */
        static Result<std::string> canonicalize_string(const std::string &json_str);

    private:
        /**
         * Serialize JSON value according to RFC 8785 rules
         */
        static void serialize_value(const nlohmann::json &value, std::string &output);

        /**
         * Serialize JSON string with proper escaping
         */
        static void serialize_string(const std::string &str, std::string &output);

        /**
         * Serialize JSON number (IEEE 754 compatible)
         */
        static void serialize_number(const nlohmann::json &num, std::string &output);

        /**
         * Serialize JSON object with sorted keys
         */
        static void serialize_object(const nlohmann::json &obj, std::string &output);

        /**
         * Serialize JSON array
         */
        static void serialize_array(const nlohmann::json &arr, std::string &output);

        /**
         * Escape string according to RFC 8785 (minimal escaping)
         */
        static std::string escape_string(const std::string &str);
    };

} // namespace sigil::json
