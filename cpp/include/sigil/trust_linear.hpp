#pragma once

#include "types.hpp"
#include <array>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace sigil
{

    struct TrustWeights
    {
        double bias;
        std::vector<double> weights;
        double threshold;

        static TrustWeights defaults();
    };

    struct TrustFeatures
    {
        static constexpr std::size_t kFeatureCount = 5;

        double action_class;
        double target_class;
        double loa_level;
        double rate_limit_recent;
        double input_entropy;

        static TrustFeatures from_inputs(
            std::string_view action,
            const std::optional<std::string_view> &target,
            const LOA &loa,
            std::size_t recent_requests,
            std::string_view input);

        std::array<double, kFeatureCount> to_array() const;
        std::vector<double> to_vector() const;
    };

    class TrustLinearModel
    {
    private:
        TrustWeights weights_;

    public:
        TrustLinearModel();
        explicit TrustLinearModel(const TrustWeights &weights);

        static TrustLinearModel with_default_weights();

        /**
         * Evaluate features and return (score, allowed)
         */
        std::pair<double, bool> evaluate(const TrustFeatures &features) const;

        void update_weights(const TrustWeights &weights);
        const TrustWeights &weights() const;
    };

    class TrustModelRegistry
    {
    private:
        std::unordered_map<std::string, TrustLinearModel> models_;
        std::string default_model_;

    public:
        TrustModelRegistry();

        void register_model(const std::string &name, const TrustLinearModel &model);
        const TrustLinearModel *get_model(const std::optional<std::string> &name) const;
        std::pair<double, bool> evaluate_with_model(
            const std::optional<std::string> &name,
            const TrustFeatures &features) const;
    };

} // namespace sigil
