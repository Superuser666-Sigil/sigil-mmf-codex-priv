#include <catch2/catch_test_macros.hpp>
#include "sigil/rate_limiter.hpp"
#include <thread>

using namespace sigil;

TEST_CASE("RateLimiter allows bursts then throttles", "[rate_limiter]")
{
    RateLimiter::Config cfg{
        10.0,  // tokens per second
        5.0    // burst
    };
    RateLimiter rl(cfg);

    // Burst should allow 5 immediate
    int allowed = 0;
    for (int i = 0; i < 5; ++i)
    {
        if (rl.allow("client"))
            ++allowed;
    }
    REQUIRE(allowed == 5);

    // Next should be throttled
    REQUIRE_FALSE(rl.allow("client"));

    // Wait for refill (0.2s -> ~2 tokens)
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    int post = 0;
    for (int i = 0; i < 3; ++i)
    {
        if (rl.allow("client"))
            ++post;
    }
    REQUIRE(post >= 1);
}
