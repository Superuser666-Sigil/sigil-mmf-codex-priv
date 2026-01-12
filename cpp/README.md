# Sigil MMF C++ Implementation

This is the C++23 translation of the Sigil MMF (Modular AI Runtime) project, originally written in Rust.

## Overview

Sigil is a modular AI runtime with the following key features:

- **LOA (Level of Access) hierarchy**: Guest → Observer → Operator → Mentor → Root
- **Cryptographic integrity**: Ed25519 signing, AES-256-GCM encryption, SHA-256 hashing
- **Canonical record management**: RFC 8785 JSON canonicalization for deterministic serialization
- **Audit logging**: Immutable audit chains with cryptographic verification
- **License validation**: TOML-based licenses with signature verification
- **Trust scoring**: Logistic regression-based trust model
- **Witness quorum**: K-of-N signature verification for system-space mutations
- **HTTP API**: RESTful endpoints for memory, RAG, quorum, and trust operations

## Build Requirements

### Dependencies

- **C++23 compatible compiler**: GCC 13+, Clang 16+, or MSVC 2022+
- **CMake 3.25+**
- **libsodium 1.0.18+** - Cryptography library (Ed25519, AES-GCM, SHA-256, Argon2)
- **RocksDB** - Embedded key-value database
- **Boost 1.82+** - For Asio (async I/O) and other utilities
- **nlohmann/json 3.11+** - JSON parsing and serialization
- **toml++** - TOML configuration parsing
- **CLI11 2.3+** - Command-line argument parsing
- **spdlog** - Structured logging
- **Catch2 3.5+** - Testing framework (auto-downloaded if not found)

### Ubuntu/Debian

```bash
sudo apt update
sudo apt install -y \
    build-essential \
    cmake \
    pkg-config \
    libsodium-dev \
    librocksdb-dev \
    libboost-all-dev \
    nlohmann-json3-dev \
    libspdlog-dev \
    libcli11-dev

# toml++ (header-only, may need manual install)
git clone https://github.com/marzer/tomlplusplus.git
sudo cp -r tomlplusplus/include/toml++ /usr/local/include/
```

### macOS (Homebrew)

```bash
brew install cmake libsodium rocksdb boost nlohmann-json tomlplusplus spdlog cli11
```

### Windows (vcpkg)

```powershell
vcpkg install libsodium rocksdb boost-asio boost-system nlohmann-json tomlplusplus spdlog cli11
```

## Building

```bash
cd cpp
mkdir build
cd build

# Configure
cmake ..

# Build
cmake --build . -j$(nproc)

# Run tests
ctest --output-on-failure
```

### Build Options

```bash
# Debug build
cmake -DCMAKE_BUILD_TYPE=Debug ..

# Release build with optimizations
cmake -DCMAKE_BUILD_TYPE=Release ..

# Specify compiler
cmake -DCMAKE_CXX_COMPILER=clang++ ..
```

## Running

```bash
# Run the executable
./sigil --help

# Run tests
./sigil_tests
```

## Project Structure

```
cpp/
├── CMakeLists.txt           # Main build configuration
├── include/sigil/           # Public headers
│   ├── types.hpp            # LOA enum, Result<T>, SigilError
│   ├── crypto.hpp           # Cryptography wrappers (Ed25519, AES-GCM, SHA-256)
│   ├── json_canonicalization.hpp  # RFC 8785 implementation
│   ├── canonical_record.hpp # Canonical record structure
│   ├── config.hpp           # Configuration management
│   ├── audit.hpp            # Audit logging
│   ├── canon_store.hpp      # Storage abstraction
│   ├── license_validator.hpp # License validation
│   ├── trust_linear.hpp     # Trust scoring
│   ├── loa_policy.hpp       # LOA enforcement
│   ├── witness_registry.hpp # Witness management
│   └── quorum_system.hpp    # Quorum verification
├── src/                     # Implementation files
│   ├── main.cpp             # Entry point
│   ├── cli.cpp              # CLI commands
│   └── *.cpp                # Module implementations
└── tests/                   # Test suite
    ├── test_crypto.cpp
    ├── test_json_canonicalization.cpp
    └── test_canonical_record.cpp
```

## Implementation Status

### ✅ Completed (Phase 1)

- [x] Project structure and CMake build system
- [x] LOA enum and error handling (`types.hpp`)
- [x] Cryptographic wrappers (`crypto.hpp`):
  - [x] Ed25519 key generation, signing, verification
  - [x] AES-256-GCM encryption/decryption
  - [x] SHA-256 hashing
  - [x] Argon2 key derivation
  - [x] Base64 encoding/decoding
  - [x] Secure random number generation
- [x] RFC 8785 JSON canonicalization (`json_canonicalization.hpp`)
- [x] Canonical record structure (`canonical_record.hpp`)
- [x] Unit tests for crypto, JSON canonicalization, and canonical records

### 🚧 In Progress (Phase 2)

- [ ] Configuration system (TOML parsing, environment variables)
- [ ] Audit logging infrastructure (spdlog integration)
- [ ] CanonStore abstract interface
- [ ] RocksDB storage backend with encryption

### 📋 Planned (Future Phases)

- [ ] License validation system
- [ ] Trust scoring (logistic model)
- [ ] LOA policy enforcement
- [ ] Witness registry
- [ ] Quorum system
- [ ] CLI implementation (CLI11)
- [ ] HTTP API server (Boost.Beast)
- [ ] Main entry point and runtime initialization
- [ ] Integration tests
- [ ] Performance benchmarks

## Testing

The project uses Catch2 for unit testing. Tests are automatically discovered and run via CTest.

```bash
# Run all tests
cd build
ctest --output-on-failure

# Run specific test
./sigil_tests "[crypto]"

# Verbose output
./sigil_tests -s
```

## Design Notes

### Rust to C++ Translation Decisions

1. **Error Handling**: Using `std::expected<T, E>` (C++23) for `Result<T, E>` pattern
2. **Async Runtime**: Initially synchronous core + thread pool, async HTTP layer later with Boost.Asio
3. **Cryptography**: libsodium over OpenSSL for simpler API closer to Rust's dalek
4. **Storage**: RocksDB for embedded key-value store (similar to sled)
5. **JSON**: nlohmann/json with custom RFC 8785 canonicalization
6. **Ownership**: RAII + smart pointers (`shared_ptr`, `unique_ptr`) replace Rust lifetimes

### RFC 8785 Compatibility

The JSON canonicalization implementation **must** produce byte-identical output to the Rust version for signature compatibility with existing records. This is verified through:

1. Unit tests with known test vectors
2. Cross-validation against Rust implementation
3. Integration tests comparing hashes/signatures

### Security Considerations

- All cryptographic operations use libsodium for constant-time implementations
- Key material is zeroed on destruction
- Sensitive data in memory is minimized
- Audit trails are immutable and cryptographically signed

## Contributing

This is a direct translation of the Rust codebase. When implementing new modules:

1. Preserve the original Rust structure and API contracts
2. Maintain signature compatibility for cryptographic operations
3. Add comprehensive unit tests
4. Document C++-specific design decisions
5. Follow C++23 best practices (concepts, ranges, coroutines where appropriate)

## License

Same as the original Sigil MMF project. See parent directory for license information.

## References

- Original Rust implementation: `../src/`
- RFC 8785 (JCS): https://datatracker.ietf.org/doc/html/rfc8785
- libsodium documentation: https://doc.libsodium.org/
- Sigil refactoring plan: `../REFRACTORING_PLAN_Sigil_MMF_MVP_ASCII.md`
- Rule-Zero manifest: `../codex_manifest_rule_zero.md`
