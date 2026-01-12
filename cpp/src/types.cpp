#include "sigil/types.hpp"

namespace sigil
{

    bool can_perform_action(LOA level, const std::string &action, const std::string & /*resource*/)
    {
        if (level == LOA::Root)
            return true;

        if (level == LOA::Mentor)
            return action == "read" || action == "write" || action == "audit" || action == "validate" || action == "train" || action == "export";

        if (level == LOA::Operator)
            return action == "read" || action == "write" || action == "audit" || action == "validate";

        if (level == LOA::Observer)
            return action == "read" || action == "audit" || action == "validate";

        // Guest
        return action == "read";
    }

    bool can_access_resource(LOA level, const std::string &resource)
    {
        switch (level)
        {
        case LOA::Root:
            return true;
        case LOA::Mentor:
            return resource.find("system") == std::string::npos && resource.find("elevation") == std::string::npos;
        case LOA::Operator:
            return resource.find("system") == std::string::npos && resource.find("admin") == std::string::npos && resource.find("elevation") == std::string::npos;
        case LOA::Observer:
            return resource.find("system") == std::string::npos && resource.find("admin") == std::string::npos && resource.find("write") == std::string::npos && resource.find("elevation") == std::string::npos;
        case LOA::Guest:
            return resource.find("public") != std::string::npos || resource.find("readonly") != std::string::npos;
        }
        return false;
    }

    std::optional<LOA> required_for_action(const std::string &action)
    {
        if (action == "read")
            return LOA::Guest;
        if (action == "audit" || action == "validate")
            return LOA::Observer;
        if (action == "write")
            return LOA::Operator;
        if (action == "train" || action == "export" || action == "elevate")
            return LOA::Mentor;
        if (action == "system")
            return LOA::Root;
        return std::nullopt;
    }

    bool can_elevate_to(LOA level, LOA target)
    {
        switch (level)
        {
        case LOA::Root:
            return true;
        case LOA::Mentor:
            return target == LOA::Root;
        case LOA::Operator:
            return target == LOA::Mentor || target == LOA::Root;
        case LOA::Observer:
            return target == LOA::Operator || target == LOA::Mentor || target == LOA::Root;
        case LOA::Guest:
            return target == LOA::Observer || target == LOA::Operator || target == LOA::Mentor || target == LOA::Root;
        }
        return false;
    }

    std::optional<LOA> next_level(LOA level)
    {
        switch (level)
        {
        case LOA::Guest:
            return LOA::Observer;
        case LOA::Observer:
            return LOA::Operator;
        case LOA::Operator:
            return LOA::Mentor;
        case LOA::Mentor:
            return LOA::Root;
        case LOA::Root:
            return std::nullopt;
        }
        return std::nullopt;
    }

    std::optional<LOA> previous_level(LOA level)
    {
        switch (level)
        {
        case LOA::Guest:
            return std::nullopt;
        case LOA::Observer:
            return LOA::Guest;
        case LOA::Operator:
            return LOA::Observer;
        case LOA::Mentor:
            return LOA::Operator;
        case LOA::Root:
            return LOA::Mentor;
        }
        return std::nullopt;
    }

    Result<void> enforce(LOA required, LOA user)
    {
        if (user >= required)
        {
            return {};
        }
        return std::unexpected(SigilError::validation(std::format(
            "Insufficient LOA: required {}, got {}",
            loa_to_string(required),
            loa_to_string(user))));
    }

    bool can_read_canon(const LOA &user_loa)
    {
        return user_loa == LOA::Observer || user_loa == LOA::Operator || user_loa == LOA::Mentor || user_loa == LOA::Root;
    }

    bool can_write_canon(const LOA &user_loa)
    {
        return user_loa == LOA::Operator || user_loa == LOA::Mentor || user_loa == LOA::Root;
    }

} // namespace sigil
