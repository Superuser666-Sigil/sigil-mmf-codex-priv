#pragma once

#include "types.hpp"
#include "canonical_record.hpp"
#include "config.hpp"
#include <optional>
#include <string>
#include <vector>
#include <memory>

namespace sigil
{

    /**
     * Abstract interface for Canon storage backends.
     * Mirrors the Rust CanonStore trait at a high level while allowing
     * different backends (e.g., RocksDB, filesystem) in C++.
     */
    class CanonStore
    {
    public:
        virtual ~CanonStore() = default;

        /**
         * Add a canonical record.
         * @param record CanonicalRecord to persist
         * @param user_loa LOA of the caller (for authorization)
         * @param sign_on_write Whether to sign before writing (backends may ignore)
         */
        virtual Result<void> add_record(
            const CanonicalRecord &record,
            const LOA &user_loa,
            bool sign_on_write) = 0;

        /**
         * List records, optionally filtered by kind.
         * @param kind Optional kind filter (e.g., "trusted_witness")
         * @param user_loa LOA of the caller (for authorization)
         */
        virtual std::vector<CanonicalRecord> list_records(
            const std::optional<std::string> &kind,
            const LOA &user_loa) = 0;
    };

#ifdef SIGIL_HAVE_ROCKSDB
    /**
     * RocksDB-backed CanonStore with optional AES-256-GCM encryption at rest.
     */
    class RocksDbCanonStore : public CanonStore
    {
    public:
        explicit RocksDbCanonStore(const StorageConfig &cfg);
        ~RocksDbCanonStore() override;

        Result<void> add_record(
            const CanonicalRecord &record,
            const LOA &user_loa,
            bool sign_on_write) override;

        std::vector<CanonicalRecord> list_records(
            const std::optional<std::string> &kind,
            const LOA &user_loa) override;

    private:
        class Impl;
        std::unique_ptr<Impl> impl_;
    };
#endif

} // namespace sigil
