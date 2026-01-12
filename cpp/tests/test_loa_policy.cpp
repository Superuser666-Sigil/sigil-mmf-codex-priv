#include <catch2/catch_test_macros.hpp>
#include "sigil/loa_policy.hpp"
#include "sigil/types.hpp"

using sigil::HttpMethod;
using sigil::LOA;
using sigil::LOAPolicyTable;
using sigil::to_method;

TEST_CASE("MVP policy exact matches", "[loa_policy]")
{
    auto policy = LOAPolicyTable::mvp_defaults();
    REQUIRE(policy.required_for(HttpMethod::Post, "/api/license/create") == LOA::Root);
    REQUIRE(policy.required_for(HttpMethod::Post, "/api/license/validate") == LOA::Observer);
    REQUIRE(policy.required_for(HttpMethod::Post, "/api/memory/write") == LOA::Operator);
    REQUIRE(policy.required_for(HttpMethod::Get, "/api/memory/list") == LOA::Observer);
    REQUIRE(policy.required_for(HttpMethod::Get, "/api/trust/status") == LOA::Guest);
}

TEST_CASE("Prefix match chooses longest prefix", "[loa_policy]")
{
    auto policy = LOAPolicyTable::mvp_defaults();
    // /api/module/ is a prefix rule; ensure longer paths still match it
    REQUIRE(policy.required_for(HttpMethod::Post, "/api/module/foo/bar") == LOA::Operator);
}

TEST_CASE("is_allowed honors defaults and denies unknown methods", "[loa_policy]")
{
    auto policy = LOAPolicyTable::mvp_defaults();

    // Known route - exact
    REQUIRE(policy.is_allowed(LOA::Root, HttpMethod::Post, "/api/license/create"));
    REQUIRE_FALSE(policy.is_allowed(LOA::Observer, HttpMethod::Post, "/api/license/create"));

    // Unknown route defaults to Observer
    REQUIRE(policy.is_allowed(LOA::Observer, HttpMethod::Get, "/api/unknown"));
    REQUIRE_FALSE(policy.is_allowed(LOA::Guest, HttpMethod::Get, "/api/unknown"));

    // Unsupported verb
    REQUIRE_FALSE(policy.is_allowed(LOA::Root, HttpMethod::Other, "/api/license/create"));
}

TEST_CASE("to_method parses common verbs", "[loa_policy]")
{
    REQUIRE(to_method("GET") == HttpMethod::Get);
    REQUIRE(to_method("POST") == HttpMethod::Post);
    REQUIRE(to_method("get") == HttpMethod::Get);
    REQUIRE(to_method("PUT") == HttpMethod::Other);
}
