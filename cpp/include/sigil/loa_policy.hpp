#pragma once

#include "types.hpp"
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sigil
{

    enum class HttpMethod
    {
        Get,
        Post,
        Other
    };

    /**
     * Minimal LOA policy table for HTTP endpoints (prefix match, longest prefix wins).
     * Mirrors Rust loa_policy.rs MVP defaults.
     */
    class LOAPolicyTable
    {
    public:
        static LOAPolicyTable mvp_defaults();

        /**
         * Return required LOA for method/path if a mapping exists (longest-prefix match).
         */
        std::optional<LOA> required_for(HttpMethod method, std::string_view path) const;

        /**
         * Evaluate whether a caller with loa is permitted for method/path.
         * Unknown endpoints default to requiring Observer.
         */
        bool is_allowed(const LOA &caller_loa, HttpMethod method, std::string_view path) const;

    private:
        struct RouteDef
        {
            HttpMethod method;
            std::string prefix;
            LOA required;
        };

        std::vector<RouteDef> routes_;
    };

    /** Convert string/verb to HttpMethod (GET/POST -> mapped, else Other). */
    HttpMethod to_method(std::string_view verb);

} // namespace sigil
