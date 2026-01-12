#include "sigil/trust_linear.hpp"
#include <unordered_set>
#include <algorithm>
#include <cmath>
#include <string>
#include <string_view>

namespace sigil
{

    TrustWeights TrustWeights::defaults()
    {
        return TrustWeights{
            -0.8,                          // bias
            {0.15, 0.15, 0.4, 0.15, 0.15}, // weights
            0.4                            // threshold
        };
    }

    TrustFeatures TrustFeatures::from_inputs(
        std::string_view action,
        const std::optional<std::string_view> &target,
        const LOA &loa,
        std::size_t recent_requests,
        std::string_view input)
    {
        double action_class;
        std::string al(action);
        std::transform(al.begin(), al.end(), al.begin(), ::tolower);
        if (al == "read" || al == "get" || al == "query" || al == "canon_read" || al == "audit_read" || al == "config_read")
            action_class = 0.1;
        else if (al == "write" || al == "update" || al == "modify" || al == "canon_write" || al == "config_write")
            action_class = 0.6;
        else if (al == "delete" || al == "remove")
            action_class = 0.9;
        else if (al == "execute" || al == "run" || al == "module_execute")
            action_class = 0.4;
        else if (al == "admin" || al == "system")
            action_class = 0.95;
        else if (al == "trust_check")
            action_class = 0.1;
        else if (al == "elevation_request")
            action_class = 0.8;
        else
            action_class = 0.5;

        double target_class = 0.5;
        if (target.has_value())
        {
            std::string t(*target);
            std::transform(t.begin(), t.end(), t.begin(), ::tolower);
            if (t == "user" || t == "profile")
                target_class = 0.3;
            else if (t == "canon" || t == "system")
                target_class = 0.9;
            else if (t == "audit" || t == "log")
                target_class = 0.8;
            else if (t == "config" || t == "settings")
                target_class = 0.7;
            else if (t == "hello" || t == "module")
                target_class = 0.2;
            else
                target_class = 0.5;
        }

        double loa_level = 0.0;
        switch (loa)
        {
        case LOA::Guest:
            loa_level = 0.0;
            break;
        case LOA::Observer:
            loa_level = 0.4;
            break;
        case LOA::Operator:
            loa_level = 0.6;
            break;
        case LOA::Mentor:
            loa_level = 0.8;
            break;
        case LOA::Root:
            loa_level = 1.0;
            break;
        }

        double rate_limit_recent = std::min(1.0, static_cast<double>(recent_requests) / 100.0);

        double input_entropy = 0.0;
        if (!input.empty())
        {
            std::unordered_set<char> unique_chars(input.begin(), input.end());
            input_entropy = std::min(1.0, static_cast<double>(unique_chars.size()) / static_cast<double>(input.size()));
        }

        return TrustFeatures{
            action_class,
            target_class,
            loa_level,
            rate_limit_recent,
            input_entropy};
    }

    std::vector<double> TrustFeatures::to_vector() const
    {
        auto arr = to_array();
        return std::vector<double>(arr.begin(), arr.end());
    }

    std::array<double, TrustFeatures::kFeatureCount> TrustFeatures::to_array() const
    {
        return {action_class, target_class, loa_level, rate_limit_recent, input_entropy};
    }

    TrustLinearModel::TrustLinearModel(const TrustWeights &weights) : weights_(weights) {}

    TrustLinearModel::TrustLinearModel() : weights_(TrustWeights::defaults()) {}

    TrustLinearModel TrustLinearModel::with_default_weights()
    {
        return TrustLinearModel(TrustWeights::defaults());
    }

    std::pair<double, bool> TrustLinearModel::evaluate(const TrustFeatures &features) const
    {
        auto feature_arr = features.to_array();
        if (feature_arr.size() != weights_.weights.size())
        {
            return {0.0, false};
        }

        double linear = weights_.bias;
        for (std::size_t i = 0; i < feature_arr.size(); ++i)
        {
            linear += feature_arr[i] * weights_.weights[i];
        }

        double score = 1.0 / (1.0 + std::exp(-linear));
        bool allowed = score >= weights_.threshold;
        return {score, allowed};
    }

    void TrustLinearModel::update_weights(const TrustWeights &weights)
    {
        weights_ = weights;
    }

    const TrustWeights &TrustLinearModel::weights() const
    {
        return weights_;
    }

    TrustModelRegistry::TrustModelRegistry()
    {
        default_model_ = "trust_linear_v1";
        models_.emplace(default_model_, TrustLinearModel::with_default_weights());
    }

    void TrustModelRegistry::register_model(const std::string &name, const TrustLinearModel &model)
    {
        models_[name] = model;
    }

    const TrustLinearModel *TrustModelRegistry::get_model(const std::optional<std::string> &name) const
    {
        const std::string &model_name = name.value_or(default_model_);
        auto it = models_.find(model_name);
        if (it == models_.end())
        {
            return nullptr;
        }
        return &it->second;
    }

    std::pair<double, bool> TrustModelRegistry::evaluate_with_model(
        const std::optional<std::string> &name,
        const TrustFeatures &features) const
    {
        auto model = get_model(name);
        if (!model)
        {
            return {0.0, false};
        }
        return model->evaluate(features);
    }

} // namespace sigil
