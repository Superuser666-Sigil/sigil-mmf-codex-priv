#pragma once

#include "types.hpp"
#include "crypto.hpp"
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>

namespace sigil
{

    struct StorageConfig
    {
        std::string rocksdb_path{"./data/rocksdb"};
        bool encrypt_at_rest{true};
    };

    struct AuditConfig
    {
        bool enabled{true};
        std::string log_path{"./logs/audit.log"};
    };

    struct QuorumConfig
    {
        std::size_t threshold{1};
    };

    struct MMFConfig
    {
        std::string tenant{"system"};
        StorageConfig storage{};
        AuditConfig audit{};
        QuorumConfig quorum{};
        std::optional<crypto::AESKey> encryption_key; // from env or derived
    };

    /**
     * ConfigLoader loads TOML configs with environment overrides and optional
     * AES-256-GCM encrypted secret blocks. When SIGIL_HAVE_TOMLPP is not
     * available, it falls back to sane defaults and environment variables.
     */
    class ConfigLoader
    {
    public:
        /** Load config from a TOML file path. Environment overrides take precedence. */
        static Result<MMFConfig> load(const std::string &path);

        /** Parse config from TOML string content. */
        static Result<MMFConfig> from_string(const std::string &toml_content);

        /** Serialize config to JSON for debugging/inspection (non-secret). */
        static nlohmann::json to_json(const MMFConfig &cfg);

        // Exposed for nested parse use; encrypted secrets support
        static Result<std::optional<std::string>> maybe_decrypt(const std::string &cipher_b64,
                                                                const crypto::AESKey &key);

    private:
        static void apply_env_overrides(MMFConfig &cfg);
    };

} // namespace sigil
