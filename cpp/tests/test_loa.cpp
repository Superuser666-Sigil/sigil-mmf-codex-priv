#include <catch2/catch_test_macros.hpp>
#include "sigil/types.hpp"

using sigil::can_access_resource;
using sigil::can_elevate_to;
using sigil::can_perform_action;
using sigil::can_read_canon;
using sigil::can_write_canon;
using sigil::enforce;
using sigil::LOA;
using sigil::next_level;
using sigil::previous_level;
using sigil::required_for_action;

TEST_CASE("enforce succeeds and fails by LOA", "[loa]")
{
    REQUIRE(enforce(LOA::Observer, LOA::Operator).has_value());
    auto fail = enforce(LOA::Mentor, LOA::Observer);
    REQUIRE_FALSE(fail.has_value());
    REQUIRE(fail.error().code == sigil::ErrorCode::ValidationError);
}

TEST_CASE("can_perform_action matches Rust mapping", "[loa]")
{
    REQUIRE(can_perform_action(LOA::Root, "export"));
    REQUIRE(can_perform_action(LOA::Mentor, "train"));
    REQUIRE(can_perform_action(LOA::Operator, "write"));
    REQUIRE(can_perform_action(LOA::Observer, "audit"));
    REQUIRE(can_perform_action(LOA::Guest, "read"));

    REQUIRE_FALSE(can_perform_action(LOA::Guest, "write"));
    REQUIRE_FALSE(can_perform_action(LOA::Observer, "export"));
    REQUIRE_FALSE(can_perform_action(LOA::Operator, "train"));
}

TEST_CASE("can_access_resource string checks", "[loa]")
{
    REQUIRE(can_access_resource(LOA::Root, "system/anything"));
    REQUIRE(can_access_resource(LOA::Mentor, "user/data"));
    REQUIRE_FALSE(can_access_resource(LOA::Mentor, "system/config"));
    REQUIRE_FALSE(can_access_resource(LOA::Operator, "admin/panel"));
    REQUIRE_FALSE(can_access_resource(LOA::Observer, "write/endpoint"));
    REQUIRE(can_access_resource(LOA::Guest, "public/readonly"));
    REQUIRE_FALSE(can_access_resource(LOA::Guest, "private"));
}

TEST_CASE("required_for_action mapping", "[loa]")
{
    REQUIRE(required_for_action("read") == LOA::Guest);
    REQUIRE(required_for_action("audit") == LOA::Observer);
    REQUIRE(required_for_action("write") == LOA::Operator);
    REQUIRE(required_for_action("train") == LOA::Mentor);
    REQUIRE(required_for_action("system") == LOA::Root);
    REQUIRE(required_for_action("unknown") == std::nullopt);
}

TEST_CASE("elevation rules", "[loa]")
{
    REQUIRE(can_elevate_to(LOA::Guest, LOA::Observer));
    REQUIRE(can_elevate_to(LOA::Observer, LOA::Operator));
    REQUIRE(can_elevate_to(LOA::Operator, LOA::Root));
    REQUIRE(can_elevate_to(LOA::Mentor, LOA::Root));
    REQUIRE(can_elevate_to(LOA::Root, LOA::Root));
    REQUIRE_FALSE(can_elevate_to(LOA::Mentor, LOA::Mentor));
}

TEST_CASE("next and previous levels", "[loa]")
{
    REQUIRE(next_level(LOA::Guest) == LOA::Observer);
    REQUIRE(next_level(LOA::Mentor) == LOA::Root);
    REQUIRE_FALSE(next_level(LOA::Root).has_value());

    REQUIRE(previous_level(LOA::Operator) == LOA::Observer);
    REQUIRE(previous_level(LOA::Root) == LOA::Mentor);
    REQUIRE_FALSE(previous_level(LOA::Guest).has_value());
}

TEST_CASE("canon read/write convenience", "[loa]")
{
    REQUIRE(can_read_canon(LOA::Observer));
    REQUIRE(can_write_canon(LOA::Operator));
    REQUIRE(can_write_canon(LOA::Root));
    REQUIRE_FALSE(can_write_canon(LOA::Observer));
    REQUIRE_FALSE(can_read_canon(LOA::Guest));
}
