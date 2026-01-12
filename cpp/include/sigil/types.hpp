#pragma once

#include <expected>
#include <string>
#include <variant>
#include <stdexcept>
#include <format>

namespace sigil
{

    /**
     * Level of Access (LOA) hierarchy
     * Maps to Rust's LOA enum from loa.rs
     */
    enum class LOA
    {
        Guest = 0,
        Observer = 1,
        Operator = 2,
        Mentor = 3,
        Root = 4
    };

    /**
     * Convert LOA to string representation
     */
    inline std::string loa_to_string(LOA loa)
    {
        switch (loa)
        {
        case LOA::Guest:
            return "Guest";
        case LOA::Observer:
            return "Observer";
        case LOA::Operator:
            return "Operator";
        case LOA::Mentor:
            return "Mentor";
        case LOA::Root:
            return "Root";
        }
        return "Unknown";
    }

    /**
     * Parse LOA from string
     */
    inline std::expected<LOA, std::string> loa_from_string(const std::string &s)
    {
        if (s == "Guest")
            return LOA::Guest;
        if (s == "Observer")
            return LOA::Observer;
        if (s == "Operator")
            return LOA::Operator;
        if (s == "Mentor")
            return LOA::Mentor;
        if (s == "Root")
            return LOA::Root;
        return std::unexpected(std::format("Invalid LOA: {}", s));
    }

    /**
     * Compare LOA levels
     */
    inline bool operator>=(LOA a, LOA b)
    {
        return static_cast<int>(a) >= static_cast<int>(b);
    }

    inline bool operator<=(LOA a, LOA b)
    {
        return static_cast<int>(a) <= static_cast<int>(b);
    }

    inline bool operator>(LOA a, LOA b)
    {
        return static_cast<int>(a) > static_cast<int>(b);
    }

    inline bool operator<(LOA a, LOA b)
    {
        return static_cast<int>(a) < static_cast<int>(b);
    }

    /**
     * Error types for Sigil operations
     * Maps to Rust's various error enums
     */
    enum class ErrorCode
    {
        ConfigError,
        CryptoError,
        ValidationError,
        StorageError,
        LicenseError,
        LOADenied,
        NotFound,
        AlreadyExists,
        InvalidInput,
        NetworkError,
        InternalError,
        IOError,
        ParsingError
    };

    /**
     * Sigil error with code and message
     */
    class SigilError : public std::runtime_error
    {
    public:
        ErrorCode code;

        SigilError(ErrorCode code, const std::string &message)
            : std::runtime_error(message), code(code) {}

        static SigilError config(const std::string &msg)
        {
            return SigilError(ErrorCode::ConfigError, msg);
        }

        static SigilError crypto(const std::string &msg)
        {
            return SigilError(ErrorCode::CryptoError, msg);
        }

        static SigilError validation(const std::string &msg)
        {
            return SigilError(ErrorCode::ValidationError, msg);
        }

        static SigilError storage(const std::string &msg)
        {
            return SigilError(ErrorCode::StorageError, msg);
        }

        static SigilError license(const std::string &msg)
        {
            return SigilError(ErrorCode::LicenseError, msg);
        }

        static SigilError loa_denied(const std::string &msg)
        {
            return SigilError(ErrorCode::LOADenied, msg);
        }

        static SigilError not_found(const std::string &msg)
        {
            return SigilError(ErrorCode::NotFound, msg);
        }

        static SigilError invalid_input(const std::string &msg)
        {
            return SigilError(ErrorCode::InvalidInput, msg);
        }
    };

    /**
     * Result type using C++23 std::expected
     * Maps to Rust's Result<T, E>
     */
    template <typename T>
    using Result = std::expected<T, SigilError>;

    // LOA policy helpers (parity with Rust loa.rs)

    /**
     * Check if this LOA level can perform a specific action on a resource
     * Resource is currently advisory (matches Rust behavior which ignores it for now)
     */
    bool can_perform_action(LOA level, const std::string &action, const std::string &resource = "");

    /**
     * Check if this LOA level can access a specific resource (string match policy)
     */
    bool can_access_resource(LOA level, const std::string &resource);

    /**
     * Minimum LOA required for an action (None if unknown action)
     */
    std::optional<LOA> required_for_action(const std::string &action);

    /**
     * Check if a LOA can elevate to a target LOA
     */
    bool can_elevate_to(LOA level, LOA target);

    /**
     * Next/previous levels in the hierarchy (if any)
     */
    std::optional<LOA> next_level(LOA level);
    std::optional<LOA> previous_level(LOA level);

    /**
     * Enforce that user LOA meets required LOA (returns SigilError on failure)
     */
    Result<void> enforce(LOA required, LOA user);

    /**
     * Convenience helpers for canonical store permissions
     */
    bool can_read_canon(const LOA &user_loa);
    bool can_write_canon(const LOA &user_loa);

} // namespace sigil
