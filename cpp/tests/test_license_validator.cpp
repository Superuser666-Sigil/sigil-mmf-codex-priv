#include <catch2/catch_test_macros.hpp>
#include "sigil/license_validator.hpp"
#include "sigil/crypto.hpp"
#include "sigil/json_canonicalization.hpp"

using namespace sigil;

#ifdef SIGIL_HAVE_TOMLPP

namespace
{
    std::string make_license_toml(const LicenseDocument &doc)
    {
        std::ostringstream oss;
        oss << "product = \"" << doc.product << "\"\n";
        oss << "holder = \"" << doc.holder << "\"\n";
        oss << "expires_at = \"" << doc.expires_at << "\"\n";
        oss << "public_key = \"" << doc.public_key_b64 << "\"\n";
        oss << "signature = \"" << doc.signature_b64 << "\"\n";
        for (auto it = doc.claims.begin(); it != doc.claims.end(); ++it)
        {
            oss << it.key() << " = " << it.value().dump() << "\n";
        }
        return oss.str();
    }

    LicenseDocument make_signed_license(const crypto::Ed25519KeyPair &kp, const std::string &expires_at)
    {
        LicenseDocument doc;
        doc.product = "Sigil";
        doc.holder = "Acme Corp";
        doc.expires_at = expires_at;
        crypto::Bytes pub_bytes(kp.public_key.begin(), kp.public_key.end());
        doc.public_key_b64 = crypto::Base64::encode(pub_bytes);
        doc.claims = nlohmann::json{{"plan", "pro"}, {"seats", 25}};

        nlohmann::json payload = {
            {"product", doc.product},
            {"holder", doc.holder},
            {"expires_at", doc.expires_at},
            {"public_key", doc.public_key_b64},
            {"claims", doc.claims}};
        auto canonical = json::RFC8785Canonicalizer::canonicalize(payload);
        crypto::Bytes msg(canonical.begin(), canonical.end());
        auto sig_arr = kp.sign(msg);
        crypto::Bytes sig_bytes(sig_arr.begin(), sig_arr.end());
        doc.signature_b64 = crypto::Base64::encode(sig_bytes);
        return doc;
    }
}

TEST_CASE("License validates with correct signature", "[license]")
{
    auto kp = crypto::Ed25519KeyPair::generate().value();
    auto doc = make_signed_license(kp, "2999-12-31T00:00:00Z");
    auto toml = make_license_toml(doc);

    auto parsed = LicenseValidator::parse_toml(toml);
    REQUIRE(parsed.has_value());

    auto valid = LicenseValidator::validate(*parsed);
    REQUIRE(valid.has_value());
}

TEST_CASE("License fails for expired timestamp", "[license]")
{
    auto kp = crypto::Ed25519KeyPair::generate().value();
    auto doc = make_signed_license(kp, "2000-01-01T00:00:00Z");
    auto toml = make_license_toml(doc);

    auto parsed = LicenseValidator::parse_toml(toml);
    REQUIRE(parsed.has_value());

    auto valid = LicenseValidator::validate(*parsed);
    REQUIRE_FALSE(valid.has_value());
}

TEST_CASE("License fails for tampered signature", "[license]")
{
    auto kp = crypto::Ed25519KeyPair::generate().value();
    auto doc = make_signed_license(kp, "2999-12-31T00:00:00Z");
    doc.signature_b64[0] = (doc.signature_b64[0] == 'A') ? 'B' : 'A';
    auto toml = make_license_toml(doc);

    auto parsed = LicenseValidator::parse_toml(toml);
    REQUIRE(parsed.has_value());

    auto valid = LicenseValidator::validate(*parsed);
    REQUIRE_FALSE(valid.has_value());
}

TEST_CASE("License fails when signature missing", "[license]")
{
    auto kp = crypto::Ed25519KeyPair::generate().value();
    auto doc = make_signed_license(kp, "2999-12-31T00:00:00Z");
    doc.signature_b64.clear();
    auto toml = make_license_toml(doc);

    auto parsed = LicenseValidator::parse_toml(toml);
    REQUIRE(parsed.has_value());

    auto valid = LicenseValidator::validate(*parsed);
    REQUIRE_FALSE(valid.has_value());
}

#else

TEST_CASE("License parsing unavailable without toml++", "[license]")
{
    auto result = LicenseValidator::parse_toml("product=\"Sigil\"");
    REQUIRE_FALSE(result.has_value());
}

#endif
