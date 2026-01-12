#pragma once

#include "types.hpp"
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <optional>

namespace sigil
{
    struct AuditEvent
    {
        std::string ts;
        std::string actor;
        std::string action;
        std::string resource;
        std::string result;
        nlohmann::json details;

        nlohmann::json to_json() const;
    };

    /**
     * AuditChain links events with hashes for tamper detection. Uses SHA-256
     * over canonical JSON of events.
     */
    class AuditChain
    {
    public:
        AuditChain();

        /** Append an event, returning its chain hash */
        std::string append(const AuditEvent &event);

        /** Last hash in the chain */
        std::optional<std::string> head() const;

        const std::vector<std::string> &hashes() const { return hashes_; }

    private:
        std::vector<std::string> hashes_;
    };

    /** Simple logger wrapper that uses spdlog when available and falls back to stdout. */
    class AuditLogger
    {
    public:
        AuditLogger();

        void log(const AuditEvent &event, const std::string &chain_hash);

    private:
        void log_json(const nlohmann::json &j);
    };

} // namespace sigil
