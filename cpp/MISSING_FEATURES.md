# Missing Features: C++ vs Rust Comparison

This document identifies features present in the Rust implementation that are missing or incomplete in the C++ translation.

## Critical Missing Features

### 1. **RFC 8785 Float Formatting** (Compatibility Risk)

The C++ canonicalizer still uses ad-hoc `std::format` rules for floating point numbers. Rust follows RFC 8785 / ECMAScript formatting, so cross-language signatures can diverge for floats (e.g., exponent formatting, trimming zeros).

**Impact:** Any payload containing floats may fail signature verification across Rust/C++.

---

### 2. **CanonicalRecord Specialized Constructors** (Partial)

**Rust has multiple specialized constructors:**

```rust
// ❌ MISSING: Create signed record with proper signing flow
pub fn new_signed(
    kind: &str, id: &str, tenant: &str, space: &str, 
    payload: Value, prev: Option<String>
) -> Result<Self, String>

// ❌ MISSING: Create from FrozenChain
pub fn from_frozen_chain(
    chain: &FrozenChain, tenant: &str, space: &str, prev: Option<&str>
) -> Result<Self, String>

// ❌ MISSING: Create from ReasoningChain
pub fn from_reasoning_chain(
    chain: &ReasoningChain, tenant: &str, space: &str, prev: Option<&str>
) -> Result<Self, String>

// ❌ MISSING: Create from TrustedKnowledgeEntry
pub fn from_trusted_entry(
    entry: &TrustedKnowledgeEntry, tenant: &str, space: &str, schema_version: u32
) -> Result<Self, String>
```

**C++ has:** `create()` plus `new_signed` (KeyManager-backed). The specialized constructors above remain TODO.

**Impact:** Boilerplate required for chain/trusted-entry flows and may drift from Rust semantics.

---

### 3. **Float/Hash Encoding Consistency** (Nuance)

`new_signed` stores the hash as Base64 of SHA-256 bytes, whereas `compute_hash()` returns hex. Rust uses hex strings. This dual representation can cause confusion and signature/verification mismatches if mixed paths are used.

**Impact:** Hash field encoding may differ depending on code path; align to Rust (hex) everywhere or document clearly.

---

### 4. **Type Parity (schema_version, ts)** (Minor)

`schema_version` and `ts` remain strings in C++; Rust uses `u32` and `DateTime<Utc>`. Conversion/validation is still missing.

**Impact:** Type drift; low risk but worth aligning for strict parity and validation.

---

## Updated Gap Summary

| Gap | Status | Priority | Notes |
|-----|--------|----------|-------|
| RFC 8785 float formatting | Missing | 🔴 | Align serializer to ECMAScript rules (Rust) |
| Hash encoding consistency | Partial | 🟡 | Standardize on hex (Rust) or document base64 usage in `new_signed` |
| Specialized constructors | Missing | 🟡 | Implement FrozenChain/Reasoning/TrustedKnowledge flows |
| Type parity (`schema_version`, `ts`) | Missing | 🟢 | Switch to u32/DateTime parsing |
| Witness verification enforcement | Partial | 🟡 | Registry-backed verification exists; add tests + stricter path |
| Integration/cross-lang tests | Missing | 🟡 | Float, witness, key-store/rotation compatibility |

## Updated Recommendations

1) Implement RFC 8785-compliant float serialization and add test vectors matching Rust.
2) Normalize hash encoding (prefer Rust hex) and update `new_signed`/compute paths to match.
3) Add specialized CanonicalRecord constructors mirroring Rust helpers.
4) Add tests for witness-registry verification and require registry path in verification APIs.
5) Add type validation (u32 schema_version, parsed timestamp) and input sanitization.
6) Add integration tests: cross-language signatures, encrypted key-store load/rotate, canonical JSON with floats.

## Files to Touch Next

- `cpp/src/json_canonicalization.cpp` – float formatting
- `cpp/src/canonical_record.cpp` – hash encoding consistency; constructors
- `cpp/include/sigil/canonical_record.hpp` – constructor declarations/doc updates
- `cpp/src/quorum_system.cpp` and witness registry tests – enforce registry verification
- `cpp/tests/` – add integration and float canonicalization vectors
