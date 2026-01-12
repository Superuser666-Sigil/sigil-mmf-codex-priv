#include "sigil/canon_store.hpp"
#include "sigil/crypto.hpp"
#include <nlohmann/json.hpp>
#include <stdexcept>

#ifdef SIGIL_HAVE_ROCKSDB
#include <rocksdb/db.h>
#include <rocksdb/options.h>
#endif

namespace sigil
{

#ifdef SIGIL_HAVE_ROCKSDB
    class RocksDbCanonStore::Impl
    {
    public:
        Impl(const StorageConfig &cfg)
            : encrypt_at_rest(cfg.encrypt_at_rest)
        {
            rocksdb::Options options;
            options.create_if_missing = true;
            auto status = rocksdb::DB::Open(options, cfg.rocksdb_path, &db);
            if (!status.ok())
            {
                throw std::runtime_error("RocksDB open failed: " + status.ToString());
            }

            if (encrypt_at_rest)
            {
                auto key_res = crypto::KeyManager::get_encryption_key();
                if (!key_res)
                {
                    throw std::runtime_error(std::string("Missing encryption key: ") + key_res.error().what());
                }
                encryption_key = *key_res;
            }
        }

        ~Impl()
        {
            delete db;
        }

        Result<void> add(const CanonicalRecord &record, const LOA &user_loa, bool sign_on_write)
        {
            if (!can_write_canon(user_loa))
            {
                return std::unexpected(SigilError::loa_denied("LOA insufficient to write canon"));
            }

            CanonicalRecord rec = record;
            if (sign_on_write && !rec.is_signed())
            {
                auto key_res = crypto::KeyManager::get_or_create_canon_key();
                if (!key_res)
                    return std::unexpected(key_res.error());
                auto sign_res = rec.sign(key_res->get_keypair());
                if (!sign_res)
                    return std::unexpected(sign_res.error());
            }

            auto json = rec.to_json().dump();
            std::string value = json;
            if (encrypt_at_rest && encryption_key)
            {
                auto cipher = crypto::AES256GCM::encrypt(*encryption_key,
                                                         crypto::Bytes(json.begin(), json.end()));
                if (!cipher)
                    return std::unexpected(cipher.error());
                value = crypto::Base64::encode(*cipher);
            }

            auto status = db->Put(rocksdb::WriteOptions(), rec.id, value);
            if (!status.ok())
            {
                return std::unexpected(SigilError::storage("RocksDB Put failed: " + status.ToString()));
            }
            return {};
        }

        std::vector<CanonicalRecord> list(const std::optional<std::string> &kind, const LOA &user_loa)
        {
            std::vector<CanonicalRecord> out;
            if (!can_read_canon(user_loa))
                return out;

            std::unique_ptr<rocksdb::Iterator> it(db->NewIterator(rocksdb::ReadOptions()));
            for (it->SeekToFirst(); it->Valid(); it->Next())
            {
                std::string raw = it->value().ToString();
                if (encrypt_at_rest && encryption_key)
                {
                    auto cipher = crypto::Base64::decode(raw);
                    if (!cipher)
                        continue;
                    auto plain = crypto::AES256GCM::decrypt(*encryption_key, *cipher);
                    if (!plain)
                        continue;
                    raw.assign(plain->begin(), plain->end());
                }

                try
                {
                    auto parsed = nlohmann::json::parse(raw);
                    auto rec_res = CanonicalRecord::from_json(parsed);
                    if (!rec_res)
                        continue;
                    if (kind && rec_res->kind != *kind)
                        continue;
                    out.push_back(*rec_res);
                }
                catch (...)
                {
                }
            }
            return out;
        }

    private:
        rocksdb::DB *db{nullptr};
        bool encrypt_at_rest{false};
        std::optional<crypto::AESKey> encryption_key;
    };

    RocksDbCanonStore::RocksDbCanonStore(const StorageConfig &cfg) : impl_(std::make_unique<Impl>(cfg)) {}
    RocksDbCanonStore::~RocksDbCanonStore() = default;

    Result<void> RocksDbCanonStore::add_record(const CanonicalRecord &record,
                                               const LOA &user_loa,
                                               bool sign_on_write)
    {
        return impl_->add(record, user_loa, sign_on_write);
    }

    std::vector<CanonicalRecord> RocksDbCanonStore::list_records(const std::optional<std::string> &kind,
                                                                 const LOA &user_loa)
    {
        return impl_->list(kind, user_loa);
    }
#endif // SIGIL_HAVE_ROCKSDB

} // namespace sigil
