#include "sigil/config.hpp"
#include "sigil/json_canonicalization.hpp"
#include <cstdlib>
#include <fstream>
#include <sstream>

#ifdef SIGIL_HAVE_TOMLPP
#include <toml++/toml.h>
#endif

namespace sigil
{
    namespace
    {
        std::optional<crypto::AESKey> env_encryption_key()
        {
            const char *env = std::getenv("CANON_ENCRYPTION_KEY");
            if (!env)
                return std::nullopt;
            auto decoded = crypto::Base64::decode(env);
            if (!decoded || decoded->size() != 32)
                return std::nullopt;
            crypto::AESKey key{};
            std::copy_n(decoded->begin(), 32, key.begin());
            return key;
        }

        Result<MMFConfig> defaults()
        {
            MMFConfig cfg{};
            cfg.encryption_key = env_encryption_key();
            return cfg;
        }

#ifdef SIGIL_HAVE_TOMLPP
        MMFConfig parse_toml(const toml::table &tbl, MMFConfig cfg)
        {
            if (auto tenant = tbl["tenant"].value<std::string>())
                cfg.tenant = *tenant;

            if (auto storage = tbl["storage"].as_table())
            {
                if (auto path = (*storage)["rocksdb_path"].value<std::string>())
                    cfg.storage.rocksdb_path = *path;
                if (auto enc = (*storage)["encrypt_at_rest"].value<bool>())
                    cfg.storage.encrypt_at_rest = *enc;
            }

            if (auto audit = tbl["audit"].as_table())
            {
                if (auto enabled = (*audit)["enabled"].value<bool>())
                    cfg.audit.enabled = *enabled;
                if (auto path = (*audit)["log_path"].value<std::string>())
                    cfg.audit.log_path = *path;
            }

            if (auto quorum = tbl["quorum"].as_table())
            {
                if (auto thr = (*quorum)["threshold"].value<int64_t>())
                    cfg.quorum.threshold = static_cast<std::size_t>(*thr);
            }

            // Encrypted secrets block: secrets.ciphertext (base64 of AES-GCM blob)
            if (auto secrets = tbl["secrets"].as_table())
            {
                if (auto cipher_b64 = (*secrets)["ciphertext"].value<std::string>())
                {
                    if (cfg.encryption_key)
                    {
                        auto dec = ConfigLoader::maybe_decrypt(*cipher_b64, *cfg.encryption_key);
                        if (dec && dec->has_value())
                        {
                            // Parse decrypted TOML to override sensitive fields
                            auto inner_tbl = toml::parse(dec->value());
                            cfg = parse_toml(inner_tbl, cfg);
                        }
                    }
                }
            }

            return cfg;
        }
#endif

    } // namespace

    Result<MMFConfig> ConfigLoader::load(const std::string &path)
    {
        std::ifstream file(path);
        if (!file.is_open())
        {
            return std::unexpected(SigilError::config("Unable to open config file: " + path));
        }
        std::stringstream buffer;
        buffer << file.rdbuf();
        return from_string(buffer.str());
    }

    Result<MMFConfig> ConfigLoader::from_string(const std::string &toml_content)
    {
        auto cfg_res = defaults();
        if (!cfg_res)
            return cfg_res;
        MMFConfig cfg = *cfg_res;

#ifdef SIGIL_HAVE_TOMLPP
        try
        {
            auto tbl = toml::parse(toml_content);
            cfg = parse_toml(tbl, cfg);
        }
        catch (const std::exception &e)
        {
            return std::unexpected(SigilError::config(std::string("Failed to parse TOML: ") + e.what()));
        }
#endif

        apply_env_overrides(cfg);
        return cfg;
    }

    void ConfigLoader::apply_env_overrides(MMFConfig &cfg)
    {
        if (const char *tenant = std::getenv("SIGIL_TENANT"))
            cfg.tenant = tenant;
        if (const char *path = std::getenv("SIGIL_ROCKSDB_PATH"))
            cfg.storage.rocksdb_path = path;
        if (const char *enc = std::getenv("SIGIL_ENCRYPT_AT_REST"))
            cfg.storage.encrypt_at_rest = std::string(enc) != "0";
        if (const char *audit_en = std::getenv("SIGIL_AUDIT_ENABLED"))
            cfg.audit.enabled = std::string(audit_en) != "0";
        if (const char *audit_path = std::getenv("SIGIL_AUDIT_LOG"))
            cfg.audit.log_path = audit_path;
        if (const char *q = std::getenv("SIGIL_QUORUM_THRESHOLD"))
            cfg.quorum.threshold = static_cast<std::size_t>(std::stoul(q));

        if (!cfg.encryption_key)
        {
            cfg.encryption_key = env_encryption_key();
        }
    }

    Result<std::optional<std::string>> ConfigLoader::maybe_decrypt(const std::string &cipher_b64,
                                                                   const crypto::AESKey &key)
    {
        auto cipher = crypto::Base64::decode(cipher_b64);
        if (!cipher)
            return std::unexpected(cipher.error());
        auto plain = crypto::AES256GCM::decrypt(key, *cipher);
        if (!plain)
            return std::unexpected(plain.error());
        return std::optional<std::string>(std::string(plain->begin(), plain->end()));
    }

    nlohmann::json ConfigLoader::to_json(const MMFConfig &cfg)
    {
        nlohmann::json j;
        j["tenant"] = cfg.tenant;
        j["storage"] = {
            {"rocksdb_path", cfg.storage.rocksdb_path},
            {"encrypt_at_rest", cfg.storage.encrypt_at_rest}};
        j["audit"] = {{"enabled", cfg.audit.enabled}, {"log_path", cfg.audit.log_path}};
        j["quorum"] = {{"threshold", cfg.quorum.threshold}};
        j["has_encryption_key"] = cfg.encryption_key.has_value();
        return j;
    }

} // namespace sigil
