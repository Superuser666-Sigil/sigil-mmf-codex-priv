#include "sigil/json_canonicalization.hpp"
#include <algorithm>
#include <format>
#include <cmath>
#include <limits>
#include <map>

namespace sigil::json
{

    std::string RFC8785Canonicalizer::canonicalize(const nlohmann::json &value)
    {
        std::string output;
        serialize_value(value, output);
        return output;
    }

    Result<std::string> RFC8785Canonicalizer::canonicalize_string(const std::string &json_str)
    {
        try
        {
            auto parsed = nlohmann::json::parse(json_str);
            return canonicalize(parsed);
        }
        catch (const nlohmann::json::exception &e)
        {
            return std::unexpected(SigilError::invalid_input(
                std::format("JSON parse error: {}", e.what())));
        }
    }

    void RFC8785Canonicalizer::serialize_value(const nlohmann::json &value, std::string &output)
    {
        switch (value.type())
        {
        case nlohmann::json::value_t::null:
            output += "null";
            break;

        case nlohmann::json::value_t::boolean:
            output += value.get<bool>() ? "true" : "false";
            break;

        case nlohmann::json::value_t::number_integer:
        case nlohmann::json::value_t::number_unsigned:
        case nlohmann::json::value_t::number_float:
            serialize_number(value, output);
            break;

        case nlohmann::json::value_t::string:
            serialize_string(value.get<std::string>(), output);
            break;

        case nlohmann::json::value_t::array:
            serialize_array(value, output);
            break;

        case nlohmann::json::value_t::object:
            serialize_object(value, output);
            break;

        default:
            // Should not happen with well-formed JSON
            output += "null";
            break;
        }
    }

    void RFC8785Canonicalizer::serialize_string(const std::string &str, std::string &output)
    {
        output += '"';
        output += escape_string(str);
        output += '"';
    }

    void RFC8785Canonicalizer::serialize_number(const nlohmann::json &num, std::string &output)
    {
        if (num.is_number_integer())
        {
            output += std::to_string(num.get<int64_t>());
        }
        else if (num.is_number_unsigned())
        {
            output += std::to_string(num.get<uint64_t>());
        }
        else
        {
            // Floating point - use RFC 8785 rules
            double value = num.get<double>();

            // Handle special cases
            if (std::isnan(value) || std::isinf(value))
            {
                output += "null";
                return;
            }

            // Check if it's actually an integer value
            if (value == std::floor(value) && std::abs(value) < 9007199254740992.0)
            {
                output += std::format("{:.0f}", value);
            }
            else
            {
                // Use scientific notation for very large/small numbers
                // Use fixed notation for normal numbers
                if (std::abs(value) >= 1e21 || (std::abs(value) < 1e-6 && value != 0.0))
                {
                    output += std::format("{:e}", value);
                }
                else
                {
                    // Format with minimal precision (remove trailing zeros)
                    std::string formatted = std::format("{:.16g}", value);
                    output += formatted;
                }
            }
        }
    }

    void RFC8785Canonicalizer::serialize_object(const nlohmann::json &obj, std::string &output)
    {
        output += '{';

        // Sort keys lexicographically (UTF-8 byte order)
        std::map<std::string, nlohmann::json> sorted_items;
        for (auto it = obj.begin(); it != obj.end(); ++it)
        {
            sorted_items[it.key()] = it.value();
        }

        bool first = true;
        for (const auto &[key, value] : sorted_items)
        {
            if (!first)
            {
                output += ',';
            }
            first = false;

            serialize_string(key, output);
            output += ':';
            serialize_value(value, output);
        }

        output += '}';
    }

    void RFC8785Canonicalizer::serialize_array(const nlohmann::json &arr, std::string &output)
    {
        output += '[';

        bool first = true;
        for (const auto &item : arr)
        {
            if (!first)
            {
                output += ',';
            }
            first = false;
            serialize_value(item, output);
        }

        output += ']';
    }

    std::string RFC8785Canonicalizer::escape_string(const std::string &str)
    {
        std::string escaped;
        escaped.reserve(str.size());

        for (unsigned char ch : str)
        {
            // RFC 8785: Minimal escaping
            // Must escape: " (0x22), \ (0x5C), and control characters (0x00-0x1F)
            switch (ch)
            {
            case '"':
                escaped += "\\\"";
                break;
            case '\\':
                escaped += "\\\\";
                break;
            case '\b':
                escaped += "\\b";
                break;
            case '\f':
                escaped += "\\f";
                break;
            case '\n':
                escaped += "\\n";
                break;
            case '\r':
                escaped += "\\r";
                break;
            case '\t':
                escaped += "\\t";
                break;
            default:
                if (ch < 0x20)
                {
                    // Control character - use \uXXXX format
                    escaped += std::format("\\u{:04x}", static_cast<int>(ch));
                }
                else
                {
                    // Regular character (including UTF-8 continuation bytes)
                    escaped += ch;
                }
                break;
            }
        }

        return escaped;
    }

} // namespace sigil::json
