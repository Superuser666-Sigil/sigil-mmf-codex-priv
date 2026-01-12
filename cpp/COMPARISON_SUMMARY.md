# C++ Translation Comparison Summary

## Executive Summary

The C++ translation is **~60% complete** based on feature parity with the Rust implementation. Core cryptographic operations are functional, but **critical compatibility issues** and **missing key management features** prevent production use.

### Translation Status

| Component | Completeness | Status |
|-----------|--------------|--------|
| Cryptographic operations | 85% | ✅ Functional |
| JSON canonicalization | 90% | ⚠️ Needs fixes |
| Canonical record structure | 65% | ⚠️ Missing fields |
| LOA system | 35% | ⚠️ Missing logic |
| Key management | 25% | ❌ Largely missing |
| **Overall** | **60%** | ⚠️ **Not production-ready** |

---

## Critical Findings

### 🔴 Blocker Issues (Must Fix)

#### 1. **Canonical JSON Hash Field** (Compatibility Breaker)
**Problem:** C++ leaves `"hash":""` in canonical JSON; Rust removes field entirely.

**Rust:**
```rust
let mut value = serde_json::to_value(&unsigned_record)?;
if let Value::Object(ref mut map) = value {
    map.remove("hash");  // ✅ Field completely removed
}
```

**C++:**
```cpp
json j = {
    {"hash", ""}, // ❌ Empty string still present in JSON
    // ...
};
```

**Impact:** Signatures will not verify across languages.

**Fix:** Must remove hash key entirely from JSON object before canonicalization.

---

#### 2. **Missing `Link` Structure** (Feature Blocker)
**Problem:** C++ CanonicalRecord has no `links` field.

**Rust:**
```rust
pub struct CanonicalRecord {
    pub links: Vec<Link>,  // ❌ MISSING in C++
    // ...
}

pub struct Link {
    pub label: String,    // Relationship type
    pub target: String,   // Target record ID
}
```

**Impact:** Cannot represent relationships between records (parent chains, references).

**Fix:** Add Link structure and links field to CanonicalRecord.

---

#### 3. **Simplified `WitnessRecord` Format** (Metadata Loss)
**Problem:** C++ stores witnesses as JSON strings; Rust has structured metadata.

**Rust:**
```rust
pub struct WitnessRecord {
    pub witness_id: String,
    pub signature: String,
    pub timestamp: DateTime<Utc>,
    pub authority: String,
}
```

**C++:**
```cpp
std::vector<std::string> witness_signatures; // ❌ Just JSON strings
```

**Impact:** Loses witness provenance, timestamp, and authority information.

**Fix:** Implement full WitnessRecord structure.

---

#### 4. **Missing KeyStore and KeyManager** (No Key Rotation)
**Problem:** C++ has no multi-version key management.

**Rust has:**
```rust
pub struct KeyStore {
    keys: HashMap<u32, CanonSigningKey>,  // Multi-version storage
    current_key_index: u32,                // Active key
}

impl KeyManager {
    fn get_encryption_key() -> Result<[u8; 32]>     // From CANON_ENCRYPTION_KEY env
    fn get_key_directory() -> PathBuf                // From CANON_KEY_DIR env
    fn get_or_create_key_store() -> Result<KeyStore> // Load/create encrypted keys
    fn try_migrate_legacy_key() -> Result<...>       // Backward compatibility
}
```

**C++ has:** Only basic Ed25519KeyPair with generate/sign/verify.

**Impact:**
- Cannot rotate keys
- Cannot verify historical signatures (no key versioning)
- No encrypted key storage/loading
- No environment-based configuration
- No legacy key migration path

**Fix:** Implement KeyStore and KeyManager matching Rust API.

---

### 🟡 Important Gaps

#### 5. **LOA Policy Methods Missing**
**Rust has 9 additional LOA methods:**
- `can_perform_action(action, resource)` - Fine-grained authorization
- `can_access_resource(resource)` - Resource-based checks  
- `required_for_action(action)` - Static lookup table
- `can_elevate_to(target_loa)` - Elevation logic
- `next_level()`, `previous_level()` - Hierarchy navigation

**Plus 3 utility functions:**
- `enforce(required, user)` - LOA enforcement
- `can_read_canon(loa)` - Canon read permission
- `can_write_canon(loa)` - Canon write permission

**C++ has:** Only enum definition and comparison operators.

---

#### 6. **Encrypted Key Storage Lacks Metadata**
**Rust format:**
```rust
struct EncryptedKeyData {
    version: u32,                // Schema version
    encrypted_private_key_b64: String,
    public_key_b64: String,
    nonce_b64: String,
    created_at: String,          // Timestamp
    key_index: u32,              // Version number
    purpose: String,             // Description
}
```

**C++ has:** Only `{"public_key": "...", "secret_key": "..."}`

---

#### 7. **Specialized CanonicalRecord Constructors Missing**
**Rust has 4 type-specific constructors:**
- `new_signed()` - Auto-sign with KeyManager
- `from_frozen_chain()` - Create from FrozenChain
- `from_reasoning_chain()` - Create from ReasoningChain
- `from_trusted_entry()` - Create from TrustedKnowledgeEntry

**C++ has:** Only generic `create()` method.

---

### 🟢 Acceptable Trade-offs

- `schema_version`: u32 in Rust, String in C++ (works, just less type-safe)
- `ts`: DateTime<Utc> in Rust, String in C++ (works, just less ergonomic)
- Test coverage: Rust has 39 tests, C++ has 23 (acceptable for Phase 1)

---

## What Works

### ✅ Fully Functional

1. **Ed25519 cryptography** - Generate, sign, verify (compatible with Rust)
2. **AES-256-GCM encryption** - Encrypt/decrypt (compatible with Rust)
3. **SHA-256 hashing** - Hash computation (compatible with Rust)
4. **Argon2 key derivation** - Password-based KDF (compatible)
5. **Base64 encoding** - Standard and URL-safe (compatible)
6. **Basic JSON canonicalization** - Object sorting, string escaping, arrays
7. **CanonicalRecord CRUD** - Create, serialize, deserialize
8. **Basic signing/verification** - Single-key operations
9. **LOA enum** - 5-level hierarchy with comparisons

### ⚠️ Partially Working

10. **Float number formatting** - May differ from Rust (untested)
11. **Witness signatures** - Basic support but missing metadata
12. **Keypair JSON export** - Works but no encryption metadata

---

## Compatibility Assessment

### Cross-Language Operations

| Operation | Likely Status | Reason |
|-----------|---------------|--------|
| Sign in Rust, verify in C++ | ❌ Will fail | Canonical JSON mismatch (hash field) |
| Sign in C++, verify in Rust | ❌ Will fail | Canonical JSON mismatch (hash field) |
| Encrypt in Rust, decrypt in C++ | ✅ Will work | libsodium standard |
| Encrypt in C++, decrypt in Rust | ✅ Will work | libsodium standard |
| Load Rust encrypted keys in C++ | ❌ Will fail | Different JSON format |
| Load C++ encrypted keys in Rust | ❌ Will fail | Different JSON format |

### Recommendation
**Do not attempt cross-language operations until fixes are applied.**

---

## Detailed Feature Matrix

See [FEATURE_PARITY_MATRIX.md](FEATURE_PARITY_MATRIX.md) for complete comparison table.

Key findings:
- **Core Cryptography:** 85% complete (missing KeyStore/KeyManager)
- **JSON Canonicalization:** 90% complete (needs hash field fix)
- **Canonical Record:** 65% complete (missing links, witnesses)
- **LOA System:** 35% complete (missing 12 methods/functions)
- **Key Management:** 25% complete (minimal functionality)

---

## Implementation Roadmap

### Phase 2A: Critical Fixes (2-3 days)
**Goal:** Achieve cross-language compatibility

1. ✅ **Fix `canonicalize_record()` hash field removal**
   - Remove hash key entirely from JSON before canonicalization
   - Test byte-exact match with Rust on same input

2. ✅ **Add Link and WitnessRecord structures**
   - Implement Link{label, target}
   - Implement WitnessRecord{witness_id, signature, timestamp, authority}
   - Add links field to CanonicalRecord
   - Update add_witness_signature() to use full structure

3. ✅ **Verify float number formatting**
   - Test edge cases: 0.0, -0.0, 1.0, 1e-10, 1e20, PI
   - Compare output byte-for-byte with Rust
   - Adjust formatting logic if needed

4. ✅ **Add cross-validation tests**
   - Test: sign in Rust, load & verify in C++
   - Test: sign in C++, load & verify in Rust
   - Test: canonical JSON byte-exact match
   - Test: encrypted data cross-decrypt

**Deliverable:** C++ can correctly verify Rust-signed records.

---

### Phase 2B: Key Management (3-4 days)
**Goal:** Implement production-grade key lifecycle

5. ✅ **Implement KeyStore class**
   - HashMap<uint32_t, Ed25519KeyPair> keys
   - uint32_t current_key_index
   - rotate_key() - Generate new key, increment index
   - get_key(index) - Retrieve historical key
   - current_key() - Get active key
   - key_indices() - List all versions

6. ✅ **Implement KeyManager class**
   - get_encryption_key() - Read CANON_ENCRYPTION_KEY env var
   - get_key_directory() - Read CANON_KEY_DIR env var or default
   - get_or_create_key_store() - Load or create encrypted key store
   - try_migrate_legacy_key() - Import unencrypted keys
   - verify_key_store() - Test all keys

7. ✅ **Add encrypted key storage with metadata**
   - EncryptedKeyData structure with version, created_at, key_index, purpose
   - KeyStore::load_from_directory()
   - KeyStore::save_to_directory()
   - Filename format: `canon_key_0001.json`, `canon_key_0002.json`, etc.

8. ✅ **Test key rotation and migration**
   - Test: rotate key 3 times, verify all keys work
   - Test: save encrypted keys, reload, verify integrity
   - Test: migrate legacy key, verify in new store
   - Test: historical signature verification

**Deliverable:** Production-ready key management matching Rust behavior.

---

### Phase 2C: LOA System (2 days)
**Goal:** Complete authorization logic

9. ✅ **Add LOA policy methods**
   - can_perform_action(action, resource)
   - can_access_resource(resource)
   - required_for_action(action)
   - can_elevate_to(target_loa)
   - next_level(), previous_level()

10. ✅ **Add LOA utility functions**
    - enforce(required, user) → Result<void>
    - can_read_canon(loa) → bool
    - can_write_canon(loa) → bool

11. ✅ **Add unit tests**
    - Test all 9 methods
    - Test 3 utility functions
    - Test LOA hierarchy edge cases

**Deliverable:** Complete LOA authorization matching Rust.

---

### Phase 2D: Specialized Constructors (1-2 days)
**Goal:** Type-safe record creation

12. ✅ **Add CanonicalRecord constructors**
    - new_signed(kind, id, tenant, space, payload, prev)
    - from_frozen_chain(chain, tenant, space, prev)
    - from_reasoning_chain(chain, tenant, space, prev)
    - from_trusted_entry(entry, tenant, space, schema_version)

**Deliverable:** Ergonomic record creation matching Rust API.

---

### Phase 2E: Configuration System (already planned)
Continue with original Phase 2 plan: config.hpp, audit.hpp, canon_store.hpp.

---

## Testing Strategy

### Unit Tests (Current: 23, Target: 50+)

**Add:**
- KeyStore operations (10 tests)
- KeyManager environment loading (5 tests)
- LOA policy methods (12 tests)
- Cross-language signature verification (5 tests)
- Float formatting edge cases (5 tests)
- Canonical JSON hash field removal (3 tests)

### Integration Tests (New)

**Create:**
- Rust→C++ record verification test harness
- C++→Rust record verification test harness
- Key file format compatibility tests
- Encrypted data cross-decrypt tests

### Regression Tests

**Ensure:**
- Rust test suite passes (cargo test)
- C++ test suite passes (ctest)
- Cross-validation suite passes

---

## Risk Mitigation

### High Risk: Canonical JSON Incompatibility
**Mitigation:** 
- Fix hash field removal immediately
- Add byte-exact comparison tests
- Test on 100+ sample records from Rust

### High Risk: Float Formatting Differences
**Mitigation:**
- Test all float edge cases from Rust test suite
- If incompatible, adopt exact Rust logic
- Document any deliberate deviations

### Medium Risk: KeyStore API Mismatch
**Mitigation:**
- Copy Rust interface exactly
- Test rotation scenarios end-to-end
- Verify historical signature validation

### Low Risk: LOA Logic Errors
**Mitigation:**
- Port Rust tests directly
- Use same test data
- Cross-reference authorization decisions

---

## Success Criteria

### Phase 2A Success (Critical Fixes)
- [ ] Sign record in Rust, verify in C++ ✅
- [ ] Sign record in C++, verify in Rust ✅
- [ ] Canonical JSON byte-exact match on 100 test cases ✅
- [ ] All existing tests still pass ✅

### Phase 2B Success (Key Management)
- [ ] Rotate keys 10 times, verify all work ✅
- [ ] Save/load encrypted key store ✅
- [ ] Migrate legacy key successfully ✅
- [ ] Verify historical signatures ✅

### Phase 2C Success (LOA System)
- [ ] All 12 LOA methods/functions implemented ✅
- [ ] Behavior matches Rust exactly ✅
- [ ] Unit tests pass ✅

### Phase 2 Complete Success
- [ ] Feature parity: 85%+ ✅
- [ ] Cross-language operations work ✅
- [ ] No critical compatibility issues ✅
- [ ] Production-ready key management ✅

---

## Effort Estimate

| Phase | Days | Person-Days |
|-------|------|-------------|
| 2A: Critical Fixes | 2-3 | 2-3 |
| 2B: Key Management | 3-4 | 3-4 |
| 2C: LOA System | 2 | 2 |
| 2D: Constructors | 1-2 | 1-2 |
| Testing & Documentation | 2 | 2 |
| **Total Phase 2** | **10-13 days** | **10-13** |

With 1 developer: **2-3 weeks**
With 2 developers: **1-1.5 weeks** (parallelizable)

---

## Conclusion

The C++ translation has a solid foundation (60% complete) but requires critical fixes before production use:

**Must Fix:**
1. Canonical JSON hash field removal
2. Add Link and WitnessRecord structures  
3. Implement KeyStore and KeyManager
4. Verify float formatting compatibility

**Should Fix:**
5. Complete LOA policy system
6. Add specialized constructors
7. Add comprehensive cross-validation tests

Once Phase 2A-2D are complete, the C++ implementation will be:
- ✅ Cryptographically compatible with Rust
- ✅ Production-ready key management
- ✅ Complete authorization logic
- ✅ ~85% feature parity
- ✅ Ready for production deployment

**Estimated completion:** 2-3 weeks with 1 developer.

---

## Next Steps

1. Review MISSING_FEATURES.md for detailed gap analysis
2. Review FEATURE_PARITY_MATRIX.md for complete comparison
3. Begin Phase 2A critical fixes
4. Set up cross-validation test framework
5. Continue with remaining Phase 2 components

**Current focus:** Fix canonical JSON compatibility (highest priority blocker).
