#include <catch2/catch_test_macros.hpp>
#include "sigil/json_canonicalization.hpp"

using namespace sigil::json;
using json = nlohmann::json;

TEST_CASE("RFC 8785 - Simple object canonicalization", "[json]")
{
    json obj = {
        {"z", 3},
        {"a", 1},
        {"m", 2}};

    std::string canonical = RFC8785Canonicalizer::canonicalize(obj);
    REQUIRE(canonical == R"({"a":1,"m":2,"z":3})");
}

TEST_CASE("RFC 8785 - Nested object canonicalization", "[json]")
{
    json obj = {
        {"outer", {{"z", "last"}, {"a", "first"}}}};

    std::string canonical = RFC8785Canonicalizer::canonicalize(obj);
    REQUIRE(canonical == R"({"outer":{"a":"first","z":"last"}})");
}

TEST_CASE("RFC 8785 - Array canonicalization", "[json]")
{
    json arr = {1, 2, 3};
    std::string canonical = RFC8785Canonicalizer::canonicalize(arr);
    REQUIRE(canonical == "[1,2,3]");
}

TEST_CASE("RFC 8785 - String escaping", "[json]")
{
    json obj = {
        {"quote", "He said \"hello\""},
        {"newline", "line1\nline2"},
        {"tab", "a\tb"}};

    std::string canonical = RFC8785Canonicalizer::canonicalize(obj);
    REQUIRE(canonical.find("\\\"") != std::string::npos);
    REQUIRE(canonical.find("\\n") != std::string::npos);
    REQUIRE(canonical.find("\\t") != std::string::npos);
}

TEST_CASE("RFC 8785 - Number formatting", "[json]")
{
    json obj = {
        {"int", 42},
        {"negative", -17},
        {"zero", 0}};

    std::string canonical = RFC8785Canonicalizer::canonicalize(obj);
    REQUIRE(canonical == R"({"int":42,"negative":-17,"zero":0})");
}

TEST_CASE("RFC 8785 - Boolean and null", "[json]")
{
    json obj = {
        {"bool_true", true},
        {"bool_false", false},
        {"null_val", nullptr}};

    std::string canonical = RFC8785Canonicalizer::canonicalize(obj);
    REQUIRE(canonical == R"({"bool_false":false,"bool_true":true,"null_val":null})");
}

TEST_CASE("RFC 8785 - Control character escaping", "[json]")
{
    std::string str_with_ctrl = "test\x01\x1F";
    json obj = {{"ctrl", str_with_ctrl}};

    std::string canonical = RFC8785Canonicalizer::canonicalize(obj);
    REQUIRE(canonical.find("\\u0001") != std::string::npos);
    REQUIRE(canonical.find("\\u001f") != std::string::npos);
}

TEST_CASE("RFC 8785 - Empty structures", "[json]")
{
    REQUIRE(RFC8785Canonicalizer::canonicalize(json::object()) == "{}");
    REQUIRE(RFC8785Canonicalizer::canonicalize(json::array()) == "[]");
}

TEST_CASE("RFC 8785 - Determinism test", "[json]")
{
    json obj = {
        {"z", 1},
        {"a", 2},
        {"nested", {{"y", 3}, {"b", 4}}},
        {"array", {9, 8, 7}}};

    std::string canon1 = RFC8785Canonicalizer::canonicalize(obj);
    std::string canon2 = RFC8785Canonicalizer::canonicalize(obj);

    REQUIRE(canon1 == canon2);
    REQUIRE(canon1 == R"({"a":2,"array":[9,8,7],"nested":{"b":4,"y":3},"z":1})");
}
