# Sigil C++ Translation - Build & Development Guide

## Quick Start

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt install -y build-essential cmake pkg-config \
    libsodium-dev librocksdb-dev libboost-all-dev \
    nlohmann-json3-dev libspdlog-dev libcli11-dev

# Clone toml++ (header-only)
git clone https://github.com/marzer/tomlplusplus.git
sudo cp -r tomlplusplus/include/toml++ /usr/local/include/

# Build
cd cpp
mkdir build && cd build
cmake ..
cmake --build . -j$(nproc)

# Test
ctest --output-on-failure
```

## Development Workflow

### 1. Adding New Modules

When translating a new Rust module:

```bash
# 1. Create header in include/sigil/
touch include/sigil/new_module.hpp

# 2. Create implementation in src/
touch src/new_module.cpp

# 3. Create tests in tests/
touch tests/test_new_module.cpp

# 4. Update CMakeLists.txt
# Add to SIGIL_SOURCES list

# 5. Rebuild
cd build
cmake --build .
```

### 2. Running Specific Tests

```bash
# List all tests
./sigil_tests --list-tests

# Run specific test suite
./sigil_tests "[crypto]"

# Run specific test case
./sigil_tests "Ed25519 signing and verification"

# Verbose output
./sigil_tests -s
```

### 3. Debugging

```bash
# Debug build
cmake -DCMAKE_BUILD_TYPE=Debug ..
cmake --build .

# Run with gdb
gdb ./sigil_tests

# Run with valgrind (memory leaks)
valgrind --leak-check=full ./sigil_tests
```

## Dependency Details

### Critical Dependencies

| Library | Version | Purpose | Installation |
|---------|---------|---------|--------------|
| libsodium | 1.0.18+ | Cryptography (Ed25519, AES-GCM, SHA-256) | `apt install libsodium-dev` |
| RocksDB | Latest | Key-value storage | `apt install librocksdb-dev` |
| Boost | 1.82+ | Asio (async I/O), utilities | `apt install libboost-all-dev` |
| nlohmann/json | 3.11+ | JSON parsing | `apt install nlohmann-json3-dev` |
| toml++ | Latest | TOML parsing | Manual install (header-only) |
| spdlog | Latest | Logging | `apt install libspdlog-dev` |
| CLI11 | 2.3+ | CLI parsing | `apt install libcli11-dev` |

### Optional Dependencies

- **Catch2 3.5+**: Testing framework (auto-downloaded if not found)
- **Google Benchmark**: Performance testing (future)

## CMake Configuration Options

```bash
# C++23 standard (required)
cmake -DCMAKE_CXX_STANDARD=23 ..

# Compiler warnings as errors
cmake -DCMAKE_CXX_FLAGS="-Wall -Wextra -Werror" ..

# Sanitizers (AddressSanitizer + UndefinedBehaviorSanitizer)
cmake -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined" ..

# Code coverage
cmake -DCMAKE_CXX_FLAGS="--coverage" ..
```

## Porting Checklist

For each Rust module being translated:

- [ ] Read original Rust source thoroughly
- [ ] Identify external dependencies and C++ equivalents
- [ ] Create header with matching API surface
- [ ] Implement core functionality
- [ ] Port error handling (`Result<T,E>` → `std::expected`)
- [ ] Port async patterns (if any)
- [ ] Create comprehensive unit tests
- [ ] Verify cryptographic operations match Rust output
- [ ] Document C++-specific design decisions
- [ ] Update CMakeLists.txt
- [ ] Update README implementation status

## Testing Strategy

### Unit Tests

Located in `tests/`, one file per module:

- `test_crypto.cpp` - Cryptographic operations
- `test_json_canonicalization.cpp` - RFC 8785 compliance
- `test_canonical_record.cpp` - Record signing/verification

### Integration Tests

(Future) Cross-compatibility tests:

- Compare JSON canonicalization output with Rust
- Verify signatures can be validated across Rust/C++ boundary
- Test round-trip serialization

### Performance Tests

(Future) Benchmarks:

- Cryptographic operations
- JSON canonicalization
- Storage layer throughput

## Common Issues

### libsodium not found

```bash
# Check pkg-config
pkg-config --modversion libsodium

# If missing, install:
sudo apt install libsodium-dev pkg-config
```

### RocksDB not found

```bash
# Install from package manager
sudo apt install librocksdb-dev

# Or build from source:
git clone https://github.com/facebook/rocksdb.git
cd rocksdb
make shared_lib
sudo make install
```

### toml++ not found

```bash
# Header-only library, manual install:
git clone https://github.com/marzer/tomlplusplus.git
sudo cp -r tomlplusplus/include/toml++ /usr/local/include/
```

### C++23 features not available

Ensure compiler supports C++23:

```bash
# GCC 13+
g++ --version

# Clang 16+
clang++ --version

# Update if needed:
sudo apt install g++-13
export CXX=g++-13
```

## Next Steps

See [README.md](README.md) for full project overview and implementation roadmap.
