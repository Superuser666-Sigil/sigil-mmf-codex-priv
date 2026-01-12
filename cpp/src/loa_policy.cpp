#include "sigil/loa_policy.hpp"
#include <array>

namespace sigil
{

    namespace
    {
        struct StaticRouteDef
        {
            HttpMethod method;
            std::string_view prefix;
            LOA required;
        };

        constexpr std::array<StaticRouteDef, 12> kMvpRoutes = {
            StaticRouteDef{HttpMethod::Post, "/api/license/create", LOA::Root},
            StaticRouteDef{HttpMethod::Post, "/api/license/bootstrap", LOA::Root},
            StaticRouteDef{HttpMethod::Post, "/api/license/validate", LOA::Observer},
            StaticRouteDef{HttpMethod::Post, "/api/canon/system/commit", LOA::Root},
            StaticRouteDef{HttpMethod::Post, "/api/canon/system/propose", LOA::Root},
            StaticRouteDef{HttpMethod::Post, "/api/canon/system/attest", LOA::Root},
            StaticRouteDef{HttpMethod::Post, "/api/memory/write", LOA::Operator},
            StaticRouteDef{HttpMethod::Get, "/api/memory/list", LOA::Observer},
            StaticRouteDef{HttpMethod::Post, "/api/rag/upsert", LOA::Operator},
            StaticRouteDef{HttpMethod::Post, "/api/module/", LOA::Operator}, // prefix match
            StaticRouteDef{HttpMethod::Post, "/api/trust/check", LOA::Guest},
            StaticRouteDef{HttpMethod::Get, "/api/trust/status", LOA::Guest},
        };
    } // namespace

    LOAPolicyTable LOAPolicyTable::mvp_defaults()
    {
        LOAPolicyTable table;
        table.routes_.reserve(kMvpRoutes.size());
        for (const auto &r : kMvpRoutes)
        {
            table.routes_.push_back(RouteDef{r.method, std::string{r.prefix}, r.required});
        }
        return table;
    }

    std::optional<LOA> LOAPolicyTable::required_for(HttpMethod method, std::string_view path) const
    {
        std::optional<LOA> best;
        std::size_t best_len = 0;

        for (const auto &r : routes_)
        {
            if (r.method != method)
                continue;

            if (path.starts_with(r.prefix) && r.prefix.size() > best_len)
            {
                best = r.required;
                best_len = r.prefix.size();
            }
        }

        return best;
    }

    bool LOAPolicyTable::is_allowed(const LOA &caller_loa, HttpMethod method, std::string_view path) const
    {
        if (method == HttpMethod::Other)
        {
            return false; // methods other than GET/POST are denied
        }

        auto required = required_for(method, path);
        if (required)
        {
            return caller_loa >= *required;
        }

        // Default: Observer required for unknown endpoints
        return caller_loa >= LOA::Observer;
    }

    HttpMethod to_method(std::string_view verb)
    {
        if (verb == "GET" || verb == "get")
            return HttpMethod::Get;
        if (verb == "POST" || verb == "post")
            return HttpMethod::Post;
        return HttpMethod::Other;
    }

} // namespace sigil
