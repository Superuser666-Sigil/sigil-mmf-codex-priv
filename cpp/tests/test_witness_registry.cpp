#include <catch2/catch_test_macros.hpp>
#include "sigil/canonical_record.hpp"
#include "sigil/witness_registry.hpp"
#include "sigil/canon_store.hpp"
#include "sigil/crypto.hpp"

using namespace sigil;

namespace {
    class InMemoryCanonStore : public CanonStore {
    public:
        Result<void> add_record(const CanonicalRecord &record, const LOA &user_loa, bool /*sign_on_write*/) override {
            if (!can_write_canon(user_loa)) {
                return std::unexpected(SigilError::loa_denied("insufficient LOA to write"));
            }
            records_.push_back(record);
            return {};
        }

        std::vector<CanonicalRecord> list_records(const std::optional<std::string> &kind, const LOA & /*user_loa*/) override {
            if (!kind) return records_;
            std::vector<CanonicalRecord> out;
            for (const auto &r : records_) {
                if (r.kind == *kind) out.push_back(r);
            }
            return out;
        }

    private:
        std::vector<CanonicalRecord> records_;
    };

    std::string sign_message(const crypto::Ed25519KeyPair &kp, const std::string &canonical_json) {
        crypto::Bytes msg(canonical_json.begin(), canonical_json.end());
        auto sig_arr = kp.sign(msg);
        crypto::Bytes sig_bytes(sig_arr.begin(), sig_arr.end());
        return crypto::Base64::encode(sig_bytes);
    }
}

TEST_CASE("Witness signatures require registry verification", "[witness][registry]") {
    auto store = std::make_shared<InMemoryCanonStore>();
    WitnessRegistry registry(store);

    auto witness_kp = crypto::Ed25519KeyPair::generate().value();
    crypto::Bytes pub_bytes(witness_kp.public_key.begin(), witness_kp.public_key.end());
    std::string witness_pub_b64 = crypto::Base64::encode(pub_bytes);

    auto add_res = registry.add_witness("w1", witness_pub_b64, "attestor", "test witness", LOA::Root);
    REQUIRE(add_res.has_value());

    CanonicalRecord record = CanonicalRecord::create(
        "test", "rec-1", "tenant", "system", nlohmann::json{{"msg", "hello"}});

    std::string canonical = record.to_canonical_json();
    std::string sig_b64 = sign_message(witness_kp, canonical);

    record.add_witness_signature("w1", sig_b64, "attestor");

    // Without registry verification, should fail when witnesses exist
    REQUIRE_FALSE(record.verify_witness_signatures());

    auto verified = record.verify_witness_signatures_with_registry(registry);
    REQUIRE(verified.has_value());
    REQUIRE(*verified);

    SECTION("Rejects tampered signature") {
        std::string bad_sig = sig_b64;
        bad_sig[0] = (bad_sig[0] == 'A') ? 'B' : 'A';
        CanonicalRecord tampered = record;
        tampered.witnesses.clear();
        tampered.add_witness_signature("w1", bad_sig, "attestor");
        auto res = tampered.verify_witness_signatures_with_registry(registry);
        REQUIRE(res.has_value());
        REQUIRE_FALSE(*res);
    }

    SECTION("Rejects unknown witness") {
        CanonicalRecord unknown = record;
        unknown.witnesses.clear();
        unknown.add_witness_signature("w2", sig_b64, "attestor");
        auto res = unknown.verify_witness_signatures_with_registry(registry);
        REQUIRE(res.has_value());
        REQUIRE_FALSE(*res);
    }
}
