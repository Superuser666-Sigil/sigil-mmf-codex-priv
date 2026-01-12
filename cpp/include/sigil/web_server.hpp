#pragma once

#include "sigil/rate_limiter.hpp"
#include "sigil/witness_registry.hpp"
#include "sigil/quorum_system.hpp"
#include "sigil/canon_store.hpp"
#include "sigil/config.hpp"
#include <string>
#include <memory>
#include <thread>
#include <vector>
#include <cstdint>

namespace sigil
{
    struct WebServerConfig
    {
        std::uint16_t port{8080};
        std::size_t threads{std::thread::hardware_concurrency() ? std::thread::hardware_concurrency() : 4};
        RateLimiter::Config rate_limit{};
        std::shared_ptr<CanonStore> canon_store; // optional, enables registry-backed witness verification
        std::shared_ptr<WitnessRegistry> witness_registry; // optional, used if provided
        std::size_t quorum_threshold{1}; // default single-witness quorum
        MMFConfig runtime_cfg{}; // loaded config snapshot for routes
    };

    /**
     * Minimal HTTP server using Boost.Beast that exposes health, license validation,
     * and canonical record verification endpoints. Designed for production use with
     * per-client rate limiting and JSON/TOML parsing.
     */
    class WebServer
    {
    public:
        explicit WebServer(const WebServerConfig &cfg = WebServerConfig{});
        ~WebServer();

        /** Start the server and block until stopped. */
        void run();

        /** Request a stop; active connections complete gracefully. */
        void stop();

    private:
        class Impl;
        std::unique_ptr<Impl> impl_;
    };
}
