#pragma once

#include "types.hpp"
#include <chrono>
#include <mutex>
#include <unordered_map>
#include <string>

namespace sigil
{
    /**
     * Thread-safe token-bucket rate limiter keyed by client identifier.
     * Defaults: 60 requests per minute per key.
     */
    class RateLimiter
    {
    public:
        struct Config
        {
            double tokens_per_second{1.0}; // 60 per minute
            double burst_capacity{60.0};   // allow short bursts
        };

        RateLimiter();
        explicit RateLimiter(const Config &cfg);

        /** Returns true if a token is available for the given key. */
        bool allow(const std::string &key);

    private:
        struct Bucket
        {
            double tokens{0.0};
            std::chrono::steady_clock::time_point last_refill{};
        };

        void refill(Bucket &bucket, std::chrono::steady_clock::time_point now);

        Config cfg_;
        std::unordered_map<std::string, Bucket> buckets_;
        std::mutex mutex_;
    };
}
