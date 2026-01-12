# C++ vs Rust Feature Parity Matrix

## Legend
- ✅ Complete and tested
- ⚠️ Partial implementation
- ❌ Not implemented
- 🔴 Critical priority
- 🟡 Important priority
- 🟢 Low priority

---

## Core Cryptography

| Feature | Rust | C++ | Priority | Notes |
|---------|------|-----|----------|-------|
| Ed25519 key generation | ✅ | ✅ | - | libsodium |
| Ed25519 signing | ✅ | ✅ | - | Compatible |
| Ed25519 verification | ✅ | ✅ | - | Compatible |
| AES-256-GCM encryption | ✅ | ✅ | - | Compatible |
| AES-256-GCM decryption | ✅ | ✅ | - | Compatible |
| SHA-256 hashing | ✅ | ✅ | - | Compatible |
| Argon2 key derivation | ✅ | ✅ | - | Compatible |
| Base64 encoding | ✅ | ✅ | - | Compatible |
| Secure random generation | ✅ | ✅ | - | Compatible |
| **Keypair JSON export** | ✅ | ✅ | - | Compatible format |
| **Multi-version KeyStore** | ✅ | ✅ | 🟡 | Implemented with rotation/encrypted files; needs compatibility tests |
| **KeyManager (env config)** | ✅ | ✅ | 🟡 | Implemented (env dir/key); add validation/tests |
| **Encrypted key files** | ✅ | ✅ | 🟡 | Metadata captured (version/purpose/index); verify parity |
| **Legacy key migration** | ✅ | ⚠️ | 🟡 | Migration helper present; needs verification |

---

## JSON Canonicalization (RFC 8785)

| Feature | Rust | C++ | Priority | Notes |
|---------|------|-----|----------|-------|
| Object key sorting | ✅ | ✅ | - | Lexicographic |
| String escaping | ✅ | ✅ | - | Control chars |
| Array preservation | ✅ | ✅ | - | Order maintained |
| Boolean/null | ✅ | ✅ | - | Standard |
| Integer formatting | ✅ | ✅ | - | Compatible |
| **Float formatting** | ✅ | ⚠️ | 🔴 | Formatting logic not yet aligned with RFC 8785 |
| Unicode handling | ✅ | ✅ | - | UTF-8 passthrough |
| Nested structures | ✅ | ✅ | - | Recursive |
| Empty structures | ✅ | ✅ | - | {}, [] |
| **Hash field removal** | ✅ | ✅ | 🟢 | Hash/sig/pub_key/witnesses omitted from canonical form |
| Determinism | ✅ | ✅ | - | Repeatable |

---

## Canonical Record Structure

| Field | Rust Type | C++ Type | Status | Priority |
|-------|-----------|----------|--------|----------|
| kind | String | std::string | ✅ | - |
| schema_version | u32 | std::string | ⚠️ | 🟢 |
| id | String | std::string | ✅ | - |
| tenant | String | std::string | ✅ | - |
| ts | DateTime<Utc> | std::string | ⚠️ | 🟢 |
| space | String | std::string | ✅ | - |
| payload | Value | nlohmann::json | ✅ | - |
| **links** | Vec<Link> | ✅ | ✅ | 🟡 |
| prev | Option<String> | std::optional<std::string> | ✅ | - |
| hash | String | std::optional<std::string> | ✅ | - |
| pub_key | Option<String> | std::optional<std::string> | ✅ | - |
| **witnesses** | Vec<WitnessRecord> | Vec<WitnessRecord> | 🟡 | Registry-backed verification available; default path now fails if registry absent |

---

## Supporting Structures

| Structure | Rust | C++ | Priority | Notes |
|-----------|------|-----|----------|-------|
| **Link** | ✅ Full | ✅ Present | 🟢 | label/target implemented |
| **WitnessRecord** | ✅ Full metadata | ✅ Present | 🟡 | Needs registry-backed verification coverage |
| **KeyStore** | ✅ Multi-version | ✅ Present | 🟡 | Rotation implemented; add tests |
| **KeyManager** | ✅ Env config | ✅ Present | 🟡 | Env-driven dirs/keys implemented |
| **EncryptedKeyData** | ✅ With metadata | ✅ Present | 🟡 | Includes version/purpose/index/created_at |
| **KeyData (legacy)** | ✅ For migration | ⚠️ Partial | 🟡 | Migration helper present |

---

## CanonicalRecord Methods

| Method | Rust | C++ | Priority | Notes |
|--------|------|-----|----------|-------|
| create() | ✅ | ✅ | - | Basic constructor |
| **new_signed()** | ✅ | ✅ | 🟡 | Implemented using KeyManager; needs tests |
| **from_frozen_chain()** | ✅ | ❌ | 🟡 | Specialized constructor |
| **from_reasoning_chain()** | ✅ | ❌ | 🟡 | Specialized constructor |
| **from_trusted_entry()** | ✅ | ❌ | 🟡 | Specialized constructor |
| to_json() | ✅ | ✅ | - | Full serialization |
| from_json() | ✅ | ✅ | - | Deserialization |
| **to_canonical_json()** | ✅ | ✅ | 🟡 | Excludes hash/sig/pub_key/witnesses; float formatting pending |
| compute_hash() | ✅ | ✅ | - | SHA-256 |
| sign() | ✅ | ✅ | - | Ed25519 signing |
| verify_signature() | ✅ | ✅ | - | Verification |
| add_witness_signature() | ✅ | ✅ | 🟢 | Includes metadata |
| verify_witness_signatures() | ✅ | ⚠️ | 🟡 | Registry-backed verification implemented; fails closed when no registry is provided |

---

## LOA System

| Feature | Rust | C++ | Priority | Notes |
|---------|------|-----|----------|-------|
| LOA enum | ✅ | ✅ | - | 5 levels |
| FromStr trait | ✅ | ⚠️ | 🟢 | loa_from_string() |
| Display trait | ✅ | ⚠️ | 🟢 | loa_to_string() |
| Comparison operators | ✅ | ✅ | - | >=, <=, >, < |
| **can_perform_action()** | ✅ | ✅ | 🟡 | Implemented policy; verify parity |
| **can_access_resource()** | ✅ | ✅ | 🟡 | Implemented string-match policy |
| **required_for_action()** | ✅ | ✅ | 🟡 | Implemented lookup |
| **can_elevate_to()** | ✅ | ✅ | 🟡 | Implemented |
| **next_level()** | ✅ | ✅ | 🟢 | Implemented |
| **previous_level()** | ✅ | ✅ | 🟢 | Implemented |
| **enforce()** | ✅ | ✅ | 🟡 | Implemented |
| **can_read_canon()** | ✅ | ✅ | 🟡 | Implemented |
| **can_write_canon()** | ✅ | ✅ | 🟡 | Implemented |

---

## Error Handling

| Feature | Rust | C++ | Notes |
|---------|------|-----|-------|
| Result\<T, E\> | ✅ | ✅ | std::expected |
| KeyError enum | ✅ | ⚠️ | SigilError generic |
| thiserror derive | ✅ | - | Not applicable |
| Error context | ✅ | ⚠️ | Basic messages |

---

## Testing

| Feature | Rust | C++ | Status |
|---------|------|-----|--------|
| Unit tests - crypto | ✅ 8 tests | ✅ 7 tests | Good coverage |
| Unit tests - JSON canon | ✅ 19 tests | ✅ 10 tests | C++ needs more |
| Unit tests - record | ✅ 10+ tests | ✅ 6 tests | C++ needs more |
| Unit tests - license | ✅ | ✅ 4 tests | Added parse/signature/expiry cases |
| Unit tests - witness registry | ✅ | ✅ 2 tests | Added add/validate, inactive negative |
| Unit tests - keys | ✅ 12 tests | ❌ | Not implemented |
| Integration tests | ✅ | ❌ | Not started |
| Cross-validation tests | ❌ | ❌ | Both need this |

---

## Feature Completeness Score

### Core Cryptography: 90%
- ✅ Basic operations complete
- ✅ KeyStore/KeyManager implemented with encrypted files
- 🟡 Needs migration/compatibility tests

### JSON Canonicalization: 85%
- ✅ Hash/sig/witness removal aligned
- ⚠️ Float formatting not yet RFC 8785-verified

### Canonical Record: 80%
- ✅ Structure includes links/witnesses
- ✅ new_signed implemented
- 🟡 Witness verification path needs registry coverage
- 🟡 Specialized constructors still pending

### LOA System: 80%
- ✅ Policy helpers implemented
- 🟡 Parity with Rust rules needs validation

### Key Management: 75%
- ✅ Encrypted key store/rotation, env-driven config
- 🟡 Legacy migration path needs tests

### Overall Translation: **78%**

---

## Immediate Action Items

### Must-Fix Before Production Use:

1. **Align float formatting** - RFC 8785 exactness for signatures
2. **Test KeyStore/KeyManager** - Ensure rotation/encrypted files parity
3. **Specialized CanonicalRecord constructors** - Frozen/reasoning/trusted entries

### Should-Fix for Feature Parity:

5. Add integration tests for LOA policies and canonicalization
6. Add legacy key migration verification
7. Add specialized CanonicalRecord constructors

### Nice-to-Have:

12. Convert schema_version to u32
13. Convert ts to proper DateTime type
14. Add more comprehensive test coverage
15. Add integration tests
16. Add cross-validation tests

---

## Risk Assessment

### 🔴 Critical Risks (Incompatibility)

1. **Float formatting differences** - May break signatures across languages
2. **Witness verification coverage** - Registry-backed verification not fully enforced/tests missing

### 🟡 Medium Risks (Feature Gaps)

3. **Key migration/compat tests** - Need validation of encrypted/legacy formats
4. **LOA policy parity** - Rules may differ; requires tests

### 🟢 Low Risks (Acceptable Trade-offs)

8. **String timestamps** - Works, just less type-safe
9. **String schema_version** - Works, just less type-safe
10. **Missing specialized constructors** - Can work around

---

## Compatibility Matrix

| Operation | Rust → C++ | C++ → Rust | Status |
|-----------|------------|------------|--------|
| Sign record in A, verify in B | ❓ Untested | ❓ Untested | Needs validation |
| Encrypt with A, decrypt with B | ✅ Compatible | ✅ Compatible | libsodium standard |
| Canonical JSON A == B | ❌ Likely fails | ❌ Likely fails | Hash field issue |
| Load encrypted keys | ❌ Incompatible | ❌ Incompatible | Different formats |
| Witness signatures | ❌ Incompatible | ❌ Incompatible | Different formats |

---

See [MISSING_FEATURES.md](MISSING_FEATURES.md) for detailed analysis and implementation plan.
