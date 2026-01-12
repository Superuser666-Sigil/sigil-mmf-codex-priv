# Rust to C++ Module Mapping

This document maps the original Rust source files to their C++ equivalents in the translation project.

## Status Legend
- ✅ **Complete**: Fully implemented and tested
- 🚧 **In Progress**: Partially implemented
- 📋 **Planned**: Not yet started
- 🔄 **Stub**: Placeholder file exists

---

## Core Cryptography & Data Structures

| Rust Source | C++ Equivalent | Status | Notes |
|-------------|----------------|--------|-------|
| `src/keys.rs` | `include/sigil/crypto.hpp` | ✅ | Ed25519 keypair, signing, verification |
| `src/key_manager.rs` | `include/sigil/crypto.hpp` | ✅ | Key generation, Argon2 derivation, base64 |
| `src/canonicalize.rs` | `include/sigil/json_canonicalization.hpp` | ✅ | RFC 8785 implementation |
| `src/canonical_record.rs` | `include/sigil/canonical_record.hpp` | ✅ | Record structure, signing, verification |
| `src/loa.rs` | `include/sigil/types.hpp` | ✅ | LOA enum, comparison operators |
| `src/errors.rs` | `include/sigil/types.hpp` | ✅ | SigilError, Result<T> type |

## Configuration & Security

| Rust Source | C++ Equivalent | Status | Notes |
|-------------|----------------|--------|-------|
| `src/config_loader.rs` | `include/sigil/config.hpp` | 🔄 | TOML parsing, env overrides |
| `src/config_security.rs` | `include/sigil/config.hpp` | 🔄 | AES-GCM config encryption |
| `src/config.rs` | `include/sigil/config.hpp` | 🔄 | Config structures (MMFConfig, TrustConfig) |
| `src/runtime_config.rs` | `include/sigil/config.hpp` | 🔄 | Runtime configuration |

## Storage Layer

| Rust Source | C++ Equivalent | Status | Notes |
|-------------|----------------|--------|-------|
| `src/canon_store.rs` | `include/sigil/canon_store.hpp` | 🔄 | Abstract CanonStore interface |
| `src/canon_store_sled.rs` | ❌ | 📋 | Legacy unencrypted (won't port) |
| `src/canon_store_sled_encrypted.rs` | `src/canon_store_rocksdb.cpp` | 📋 | RocksDB backend with AES-GCM |
| `src/canon_store_codex_nexus.rs` | `src/canon_store_nexus.cpp` | 📋 | Hierarchical file storage |
| `src/canon_loader.rs` | `include/sigil/canon_store.hpp` | 📋 | Record loading utilities |
| `src/canon_validator.rs` | `include/sigil/canon_store.hpp` | 📋 | Signature validation |
| `src/canon_diff_chain.rs` | `include/sigil/canon_diff.hpp` | 📋 | Diff and versioning |

## Audit & Logging

| Rust Source | C++ Equivalent | Status | Notes |
|-------------|----------------|--------|-------|
| `src/audit.rs` | `include/sigil/audit.hpp` | 🔄 | AuditEvent, circular buffer, spdlog |
| `src/audit_chain.rs` | `include/sigil/audit_chain.hpp` | 📋 | ReasoningChain, FrozenChain |
| `src/audit_store.rs` | `include/sigil/audit.hpp` | 📋 | Persistent audit storage |
| `src/audit_verifier.rs` | `include/sigil/audit.hpp` | 📋 | Chain verification |
| `src/secure_audit_chain.rs` | `include/sigil/audit.hpp` | 📋 | Cryptographic audit chain |
| `src/log_sink.rs` | `include/sigil/audit.hpp` | 📋 | Logging infrastructure |

## License & Trust

| Rust Source | C++ Equivalent | Status | Notes |
|-------------|----------------|--------|-------|
| `src/license_validator.rs` | `include/sigil/license_validator.hpp` | 🔄 | TOML parsing, signature verification |
| `src/loa_policy.rs` | `include/sigil/loa_policy.hpp` | 🔄 | Centralized policy table |
| `src/trust_linear.rs` | `include/sigil/trust_linear.hpp` | 🔄 | Logistic trust model |
| `src/trust_registry.rs` | `include/sigil/trust_registry.hpp` | 📋 | Trust score storage |

## Witness & Quorum

| Rust Source | C++ Equivalent | Status | Notes |
|-------------|----------------|--------|-------|
| `src/witness_registry.rs` | `include/sigil/witness_registry.hpp` | 🔄 | Trusted key management |
| `src/quorum_system.rs` | `include/sigil/quorum_system.hpp` | 🔄 | K-of-N verification |
| `src/elevation_verifier.rs` | `include/sigil/quorum_system.hpp` | 📋 | Privilege elevation |

## Session & Security

| Rust Source | C++ Equivalent | Status | Notes |
|-------------|----------------|--------|-------|
| `src/session_context.rs` | `include/sigil/session.hpp` | 📋 | Session metadata, RAII cleanup |
| `src/security.rs` | `include/sigil/security.hpp` | 📋 | License extraction from headers |
| `src/csrf_protection.rs` | `include/sigil/security.hpp` | 📋 | CSRF token validation |
| `src/rate_limiter.rs` | `include/sigil/rate_limiter.hpp` | 📋 | Token bucket rate limiting |
| `src/input_validator.rs` | `include/sigil/validation.hpp` | 📋 | Input sanitization |

## Module System

| Rust Source | C++ Equivalent | Status | Notes |
|-------------|----------------|--------|-------|
| `src/module_loader.rs` | `include/sigil/module_loader.hpp` | 📋 | Dynamic module loading (Boost.DLL) |
| `src/module_scope.rs` | `include/sigil/module_scope.hpp` | 📋 | LOA-based module permissions |
| `src/extension_runtime.rs` | `include/sigil/extensions.hpp` | 📋 | Extension execution |
| `src/extensions.rs` | `include/sigil/extensions.hpp` | 📋 | Extension traits |

## CLI & HTTP

| Rust Source | C++ Equivalent | Status | Notes |
|-------------|----------------|--------|-------|
| `src/main.rs` | `src/main.cpp` | 🔄 | Entry point, logging setup |
| `src/cli.rs` | `src/cli.cpp` | 🔄 | CLI11 subcommands |
| `src/sigilweb.rs` | `src/sigilweb.cpp` | 📋 | Boost.Beast HTTP server |
| `src/enhanced_web.rs` | `src/sigilweb.cpp` | 📋 | Enhanced LOA-aware routes |
| `src/app_state.rs` | `include/sigil/app_state.hpp` | 📋 | Shared application state |

## API Endpoints

| Rust Source | C++ Equivalent | Status | Notes |
|-------------|----------------|--------|-------|
| `src/api/memory.rs` | `src/api/memory.cpp` | 📋 | Memory write/list endpoints |
| `src/api/quorum.rs` | `src/api/quorum.cpp` | 📋 | Quorum proposal endpoints |
| `src/api/license.rs` | `src/api/license.cpp` | 📋 | License creation (Root only) |
| `src/api_errors.rs` | `include/sigil/api_errors.hpp` | 📋 | API error responses |

## Runtime Core

| Rust Source | C++ Equivalent | Status | Notes |
|-------------|----------------|--------|-------|
| `src/sigil_runtime_core.rs` | `include/sigil/runtime_core.hpp` | 📋 | Runtime orchestration |
| `src/sigil_session.rs` | `include/sigil/session.hpp` | 📋 | Session management |
| `src/sigil_vault.rs` | `include/sigil/vault.hpp` | 📋 | Secure key storage |
| `src/sigil_vault_encrypted.rs` | `include/sigil/vault.hpp` | 📋 | Encrypted vault |
| `src/sigil_encrypt.rs` | `include/sigil/crypto.hpp` | ✅ | AES-GCM encryption (integrated) |
| `src/sigil_integrity.rs` | `include/sigil/canonical_record.hpp` | ✅ | Integrity verification (integrated) |

## Utilities

| Rust Source | C++ Equivalent | Status | Notes |
|-------------|----------------|--------|-------|
| `src/canon_init_tool.rs` | `src/tools/canon_init.cpp` | 📋 | CLI tool for initialization |
| `src/sealtool.rs` | `src/tools/sealtool.cpp` | 📋 | Record sealing utility |
| `src/sigilctl.rs` | `src/tools/sigilctl.cpp` | 📋 | Root shell |
| `src/sigil_exporter.rs` | `src/tools/exporter.cpp` | 📋 | Data export |
| `src/backup_recovery.rs` | `include/sigil/backup.hpp` | 📋 | Backup/restore |
| `src/secure_file_ops.rs` | `include/sigil/file_ops.hpp` | 📋 | Secure file operations |
| `src/platform_optimizations.rs` | `include/sigil/platform.hpp` | 📋 | Platform-specific optimizations |

## Tests

| Rust Source | C++ Equivalent | Status | Notes |
|-------------|----------------|--------|-------|
| `tests/canon_roundtrip.rs` | `tests/test_canon_roundtrip.cpp` | 📋 | Serialization round-trip |
| `tests/canon_signer_integration.rs` | `tests/test_canon_signer.cpp` | 📋 | Signing integration |
| `tests/e2e_tests.rs` | `tests/test_e2e.cpp` | 📋 | End-to-end tests |
| `tests/jcs_conformance.rs` | `tests/test_json_canonicalization.cpp` | ✅ | RFC 8785 conformance |
| `tests/license.rs` | `tests/test_license_validator.cpp` | 🔄 | License validation |

---

## Implementation Priority

### Phase 1 (✅ Complete)
- Core types (LOA, Result, SigilError)
- Cryptography (Ed25519, AES-GCM, SHA-256, Argon2, base64)
- RFC 8785 JSON canonicalization
- Canonical record structure
- Unit tests for above

### Phase 2 (🚧 Current)
- Configuration system (TOML + env)
- CanonStore abstract interface
- RocksDB storage backend
- Audit logging infrastructure

### Phase 3 (📋 Next)
- License validation
- Trust scoring
- LOA policy enforcement
- Witness registry & quorum

### Phase 4 (📋 Future)
- CLI implementation
- HTTP API server
- Main entry point
- Integration tests

### Phase 5 (📋 Final)
- Module system
- Extensions
- Tools (sigilctl, sealtool)
- Performance optimization

---

## Key Translation Patterns

### Ownership
| Rust | C++ |
|------|-----|
| `T` | `T` (value) or `std::unique_ptr<T>` (owned pointer) |
| `&T` | `const T&` (immutable reference) |
| `&mut T` | `T&` (mutable reference) |
| `Arc<T>` | `std::shared_ptr<T>` |
| `Arc<Mutex<T>>` | `std::shared_ptr<std::mutex>` + data |
| `Arc<RwLock<T>>` | `std::shared_ptr<std::shared_mutex>` + data |

### Error Handling
| Rust | C++ |
|------|-----|
| `Result<T, E>` | `std::expected<T, E>` |
| `Option<T>` | `std::optional<T>` |
| `.unwrap()` | `.value()` (throws on error) |
| `.unwrap_or(default)` | `.value_or(default)` |
| `?` operator | Manual `if (!result) return std::unexpected(...)` |

### Async
| Rust | C++ |
|------|-----|
| `async fn` | `asio::awaitable<T>` (C++20 coroutines) |
| `.await` | `co_await` |
| `tokio::spawn()` | `asio::co_spawn()` |
| `tokio::Runtime` | `asio::io_context` |

### Collections
| Rust | C++ |
|------|-----|
| `Vec<T>` | `std::vector<T>` |
| `String` | `std::string` |
| `HashMap<K, V>` | `std::unordered_map<K, V>` |
| `BTreeMap<K, V>` | `std::map<K, V>` |
| `HashSet<T>` | `std::unordered_set<T>` |

---

## Cross-Compatibility Requirements

For signatures and encrypted data to be interoperable:

1. **RFC 8785 canonicalization** must produce identical output
2. **Ed25519 signatures** must verify across languages
3. **AES-256-GCM ciphertext** must decrypt across languages
4. **SHA-256 hashes** must match for same input
5. **Base64 encoding** must use same alphabet/padding

Testing strategy: Create reference data in Rust, validate in C++, and vice versa.
