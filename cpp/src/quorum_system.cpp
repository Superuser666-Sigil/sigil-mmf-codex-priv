#include "sigil/quorum_system.hpp"

namespace sigil
{

    Result<bool> QuorumSystem::verify(const CanonicalRecord &record,
                                      const WitnessRegistry &registry,
                                      std::size_t threshold)
    {
        std::size_t valid = 0;
        auto canonical = record.to_canonical_json();
        std::vector<uint8_t> msg(canonical.begin(), canonical.end());

        for (const auto &w : record.witnesses)
        {
            auto res = registry.validate_witness_signature(w.witness_id, msg, w.signature);
            if (!res)
            {
                return std::unexpected(res.error());
            }
            if (*res)
                ++valid;
            if (valid >= threshold)
                return true;
        }
        return valid >= threshold;
    }

} // namespace sigil
