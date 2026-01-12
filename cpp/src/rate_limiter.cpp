#include "sigil/rate_limiter.hpp"
#include <algorithm>

namespace sigil
{
    RateLimiter::RateLimiter() : cfg_{} {}

    RateLimiter::RateLimiter(const Config &cfg) : cfg_(cfg) {}

    void RateLimiter::refill(Bucket &bucket, std::chrono::steady_clock::time_point now)
    {
        if (bucket.last_refill.time_since_epoch().count() == 0)
        {
            bucket.last_refill = now;
            bucket.tokens = cfg_.burst_capacity;
            return;
        }
        auto elapsed = std::chrono::duration_cast<std::chrono::duration<double>>(now - bucket.last_refill).count();
        if (elapsed <= 0)
            return;
        bucket.tokens = std::min(cfg_.burst_capacity, bucket.tokens + elapsed * cfg_.tokens_per_second);
        bucket.last_refill = now;
    }

    bool RateLimiter::allow(const std::string &key)
    {
        auto now = std::chrono::steady_clock::now();
        std::lock_guard lock(mutex_);
        auto &bucket = buckets_[key];
        refill(bucket, now);
        if (bucket.tokens < 1.0)
        {
            return false;
        }
        bucket.tokens -= 1.0;
        return true;
    }

} // namespace sigil
