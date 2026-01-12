#include "sigil/audit.hpp"
#include "sigil/crypto.hpp"
#include <chrono>
#include <format>
#include <iostream>

#ifdef SIGIL_HAVE_SPDLOG
#include <spdlog/spdlog.h>
#endif

namespace sigil
{

    namespace
    {
        [[maybe_unused]] std::string now_ts()
        {
            auto now = std::chrono::system_clock::now();
            auto t = std::chrono::system_clock::to_time_t(now);
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
            std::tm tm_buf;
            gmtime_r(&t, &tm_buf);
            return std::format("{:04d}-{:02d}-{:02d}T{:02d}:{:02d}:{:02d}.{:03d}Z",
                               tm_buf.tm_year + 1900,
                               tm_buf.tm_mon + 1,
                               tm_buf.tm_mday,
                               tm_buf.tm_hour,
                               tm_buf.tm_min,
                               tm_buf.tm_sec,
                               static_cast<int>(ms.count()));
        }
    }

    nlohmann::json AuditEvent::to_json() const
    {
        return nlohmann::json{{"ts", ts},
                              {"actor", actor},
                              {"action", action},
                              {"resource", resource},
                              {"result", result},
                              {"details", details}};
    }

    AuditChain::AuditChain() = default;

    std::string AuditChain::append(const AuditEvent &event)
    {
        auto canonical = event.to_json().dump();
        auto hash = crypto::SHA256::to_hex(crypto::SHA256::hash(canonical));
        hashes_.push_back(hash);
        return hash;
    }

    std::optional<std::string> AuditChain::head() const
    {
        if (hashes_.empty())
            return std::nullopt;
        return hashes_.back();
    }

    AuditLogger::AuditLogger() = default;

    void AuditLogger::log(const AuditEvent &event, const std::string &chain_hash)
    {
        nlohmann::json j = event.to_json();
        j["chain_hash"] = chain_hash;
        log_json(j);
    }

    void AuditLogger::log_json(const nlohmann::json &j)
    {
#ifdef SIGIL_HAVE_SPDLOG
        spdlog::info(j.dump());
#else
        std::cout << j.dump() << std::endl;
#endif
    }

} // namespace sigil
