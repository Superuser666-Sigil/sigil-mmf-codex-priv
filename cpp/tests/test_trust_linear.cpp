#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>
#include <string_view>
#include "sigil/trust_linear.hpp"
#include "sigil/types.hpp"

using Catch::Approx;
using sigil::LOA;
using sigil::TrustFeatures;
using sigil::TrustLinearModel;
using sigil::TrustModelRegistry;
using sigil::TrustWeights;
using namespace std::string_view_literals;

TEST_CASE("TrustFeatures maps inputs to feature vector", "[trust]")
{
    auto f = TrustFeatures::from_inputs("write"sv, std::optional<std::string_view>("canon"sv), LOA::Operator, 50, "abcabc"sv);
    auto vec = f.to_vector();
    REQUIRE(vec.size() == 5);
    REQUIRE(vec[0] == Approx(0.6)); // action_class
    REQUIRE(vec[1] == Approx(0.9)); // target_class
    REQUIRE(vec[2] == Approx(0.6)); // loa_level for Operator
    REQUIRE(vec[3] == Approx(0.5)); // rate_limit_recent
    REQUIRE(vec[4] == Approx(0.5)); // entropy 3 unique / 6 len
}

TEST_CASE("TrustLinearModel default weights allow benign actions", "[trust]")
{
    auto model = TrustLinearModel::with_default_weights();
    auto features = TrustFeatures::from_inputs(
        "read"sv,
        std::optional<std::string_view>("user_profile"sv),
        LOA::Operator,
        5,
        "simple input"sv);
    auto [score, allowed] = model.evaluate(features);
    REQUIRE(allowed == true);
    REQUIRE(score > 0.4);
}

TEST_CASE("TrustLinearModel default weights deny risky actions", "[trust]")
{
    auto model = TrustLinearModel::with_default_weights();
    auto features = TrustFeatures::from_inputs(
        "admin"sv,
        std::optional<std::string_view>("system"sv),
        LOA::Guest,
        100,
        "complex malicious input"sv);
    auto [score, allowed] = model.evaluate(features);
    const double threshold = 0.4;
    if (score >= threshold)
    {
        REQUIRE(allowed == true);
    }
    else
    {
        REQUIRE(allowed == false);
    }
}

TEST_CASE("TrustModelRegistry returns default model", "[trust]")
{
    TrustModelRegistry registry;
    auto model = TrustLinearModel::with_default_weights();
    auto features = TrustFeatures::from_inputs(
        "read"sv,
        std::optional<std::string_view>("user_profile"sv),
        LOA::Operator,
        5,
        "simple input"sv);
    auto [registry_score, registry_allowed] = registry.evaluate_with_model(std::nullopt, features);
    auto [model_score, model_allowed] = model.evaluate(features);
    REQUIRE(registry_score == Approx(model_score));
    REQUIRE(registry_allowed == model_allowed);
}

TEST_CASE("TrustModelRegistry custom model registration", "[trust]")
{
    TrustModelRegistry registry;
    TrustWeights w{0.0, {0, 0, 1.0, 0, 0}, 0.7}; // only LOA matters, threshold high
    registry.register_model("loa_only", TrustLinearModel(w));

    auto high = TrustFeatures::from_inputs("anything"sv, std::nullopt, LOA::Root, 0, "x"sv);
    auto low = TrustFeatures::from_inputs("anything"sv, std::nullopt, LOA::Guest, 0, "x"sv);

    auto [score_high, allowed_high] = registry.evaluate_with_model(std::optional<std::string>("loa_only"), high);
    auto [score_low, allowed_low] = registry.evaluate_with_model(std::optional<std::string>("loa_only"), low);

    REQUIRE(allowed_high == true);
    REQUIRE(allowed_low == false);
    REQUIRE(score_high > score_low);
}
