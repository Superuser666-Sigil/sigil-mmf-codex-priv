#pragma once

#include "canonical_record.hpp"
#include "witness_registry.hpp"
#include <cstddef>

namespace sigil
{
    class QuorumSystem
    {
    public:
        /** Verify that at least threshold witnesses have valid signatures for the record */
        static Result<bool> verify(const CanonicalRecord &record,
                                   const WitnessRegistry &registry,
                                   std::size_t threshold);
    };
}
