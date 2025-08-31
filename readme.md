# Sigil MMF Runtime v0.1.0

**A secure, cryptographically-audited runtime for modular AI systems with hierarchical access control.**

This repository contains the `mmf_sigil` Rust crate - a production-focused runtime that enforces Level of Access (LOA) policies, validates cryptographic signatures, and maintains immutable audit trails for AI system operations.

---

## 🚀 **What's Actually Implemented**

### ✅ **Core Security Infrastructure**
- **Ed25519 Cryptographic Signatures**: Complete implementation with key generation, signing, and verification
- **Encrypted Canon Storage**: AES-GCM encrypted Sled database backend with secure key management
- **LOA (Level of Access) Enforcement**: 5-tier access control system (Guest, Observer, Operator, Mentor, Root)
- **JSON Canonicalization (RFC 8785)**: Cryptographically stable JSON representation for tamper-evident records
- **Quorum System**: Multi-party witness signatures for system-critical operations
- **CSRF Protection**: Token-based protection with configurable expiration
- **Rate Limiting**: Configurable request throttling per client

### ✅ **Audit & Trust System**
- **ReasoningChain → FrozenChain**: Two-phase audit system with mutable reasoning followed by immutable cryptographic records
- **Trust Evaluation Model**: Logistic regression model with 5 features (action risk, target risk, LOA, rate limiting, input entropy)
- **Witness Registry**: Trusted public key management for signature validation
- **Secure Audit Chain**: Cryptographically linked audit records with Ed25519 signatures

### ✅ **HTTP API (Web Interface)**
- **Trust Evaluation**: `POST /api/trust/check` - Evaluate request trustworthiness
- **Trust Status**: `GET /api/trust/status` - Runtime trust metrics
- **Canon Operations**: `POST /api/canon/user/write` - Write canonical records with full cryptographic signing
- **System Proposals**: `POST /api/canon/system/propose` - Create quorum proposals for system changes
- **System Attestation**: `POST /api/canon/system/attest` - Submit witness signatures for proposals
- **Module Execution**: `POST /api/module/{name}/run` - Execute LOA-gated modules
- **CSRF Token Minting**: `POST /api/csrf/token` - Generate CSRF protection tokens
- **Health Checks**: `/healthz`, `/readyz`, `/metrics` - Operational status endpoints

### ✅ **CLI Tools**
- **Runtime Execution**: `cargo run` - Start the main runtime with license validation
- **Web Server**: `cargo run serve --host 0.0.0.0 --port 8080` - HTTP API server
- **Canon Validation**: `cargo run validate --file canon_store` - Validate encrypted canon store
- **Key Management**: `cargo run generate-key --key-id <id>` - Generate Ed25519 keypairs
- **Digital Signing**: `cargo run sign --key-id <id> --data <data>` - Sign data with stored keys
- **Signature Verification**: `cargo run verify --key-id <id> --data <data> --signature <sig>` - Verify signatures
- **License Generation**: `cargo run generate-license` - Create signed license files
- **LOA Identity**: `cargo run whoami` - Display current access level

### ✅ **Configuration & License System**
- **TOML Configuration**: Environment and file-based configuration with secure defaults
- **License Validation**: Cryptographic license verification with LOA extraction
- **Secure Environment**: Validation of required environment variables
- **Default-Deny Security**: All operations fail closed on configuration errors

---

## 📊 **Canonical Record Format**

All persistent data uses the `CanonicalRecord` schema for cryptographic integrity:

```json
{
  "kind": "user_data | system_config | audit_record",
  "schema_version": 1,
  "id": "unique_identifier",
  "tenant": "user | system",
  "ts": "2024-01-01T00:00:00Z",
  "space": "user | system",
  "payload": { "application_specific_data": "..." },
  "links": [{ "rel": "parent", "id": "linked_record_id" }],
  "prev": "previous_record_hash_or_null",
  "hash": "sha256_of_canonical_json",
  "sig": "ed25519_signature_base64",
  "pub_key": "ed25519_public_key_base64",
  "witnesses": [
    {
      "witness_id": "mentor_1",
      "signature": "ed25519_witness_signature", 
      "timestamp": "2024-01-01T00:00:00Z",
      "authority": "signing_authority"
    }
  ]
}
```

**Cryptographic Process:**
1. Serialize to canonical JSON (RFC 8785 compliant)
2. Compute SHA256 hash of canonical bytes
3. Sign hash with Ed25519 private key
4. For system operations: collect k-of-n witness signatures
5. Store encrypted in Sled database

---

## 🔧 **Usage**

### **Installation & Build**
```bash
# Clone and build
git clone <repository>
cd sigil-mmf-codex-priv
cargo build --release

# Run tests (86 tests covering all components)
cargo test

# Generate documentation
cargo doc --open
```

### **Basic Runtime**
```bash
# Start interactive runtime (validates license, determines LOA)
cargo run

# Start HTTP API server
cargo run serve --host 0.0.0.0 --port 8080
```

### **Key Management**
```bash
# Generate a new Ed25519 keypair
cargo run generate-key --key-id my_key --output ./keys/

# Sign data
cargo run sign --key-id my_key --data "Hello World" --output signature.txt

# Verify signature
cargo run verify --key-id my_key --data "Hello World" --signature <base64_sig>
```

### **Canon Operations**
```bash
# Validate encrypted canon store
cargo run validate --file canon_store

# Query canonical records (requires proper LOA)
curl -X POST http://localhost:8080/api/trust/check \
  -H "Content-Type: application/json" \
  -d '{"action": "read", "target": "user_profile"}'
```

---

## 🏗️ **Architecture**

```
┌─────────────────┐    ┌───────────────────┐    ┌─────────────────┐
│   HTTP API      │    │  Sigil Runtime    │    │ Encrypted Canon │
│  (sigilweb)     │ ── │     Core          │ ── │   Store (Sled)  │
│                 │    │                   │    │                 │
│ • Trust Check   │    │ • LOA Enforcement │    │ • AES-GCM       │
│ • Canon Write   │    │ • Trust Model     │    │ • Ed25519 Sigs  │
│ • Module Run    │    │ • Audit Chain     │    │ • JSON Canon    │
│ • CSRF Tokens   │    │ • Quorum System   │    │ • Witness Sigs  │
└─────────────────┘    └───────────────────┘    └─────────────────┘
         │                       │                       │
         └───────── CLI Interface ───────────────────────┘
           • Key Management  • License Validation
           • Canon Validate  • Signature Tools
```

**Component Responsibilities:**
- **SigilRuntimeCore**: Trust evaluation, LOA enforcement, audit generation
- **CanonStore**: Encrypted persistence with cryptographic integrity
- **QuorumSystem**: Multi-party approval for system-critical operations
- **WitnessRegistry**: Management of trusted Ed25519 public keys
- **TrustLinearModel**: Logistic regression for request risk assessment

---

## 🔒 **Security Model**

### **Level of Access (LOA) Hierarchy**
1. **Guest**: Read-only, public information access
2. **Observer**: Diagnostic and monitoring capabilities
3. **Operator**: Module execution, limited canon writes
4. **Mentor**: Witness signatures, elevated operations
5. **Root**: System administration, all privileges

### **Cryptographic Guarantees**
- **Ed25519 Signatures**: All canon records cryptographically signed
- **Witness Quorum**: System operations require Root + 3 Mentors
- **Encryption at Rest**: AES-GCM with secure key derivation
- **Canonical JSON**: RFC 8785 compliance for signature stability
- **Audit Immutability**: ReasoningChain → FrozenChain prevents tampering

### **Default-Deny Principles**
- All operations fail closed on missing permissions
- Trust evaluation defaults to denial on errors
- License validation required for elevated access
- CSRF protection mandatory for state-changing operations

---

## 📈 **Testing & Verification**

**86 comprehensive tests covering:**
- ✅ Ed25519 key generation, signing, and verification
- ✅ Encrypted canon store operations with proper LOA enforcement
- ✅ Quorum proposal creation and witness signature collection
- ✅ JSON canonicalization RFC 8785 compliance
- ✅ Trust model evaluation with risk differentiation
- ✅ Module execution with LOA gating
- ✅ CSRF token generation and validation
- ✅ Rate limiting across multiple clients
- ✅ Audit chain integrity and tamper detection
- ✅ Complete canon write/verify round-trip with witnesses

**Test Coverage:**
```bash
cargo test --lib  # Runs all 86 tests
cargo test --lib test_canon_write_verify_round_trip_with_quorum -- --nocapture  # See full workflow
```

---

## ⚙️ **Configuration**

**Environment Variables:**
```bash
MMF_LICENSE_SECRET="your_license_secret"
MMF_DB_BACKEND="sled"  # Default encrypted storage
MMF_IRL_THRESHOLD="0.4"  # Trust evaluation threshold
MMF_IRL_ENFORCEMENT_MODE="active"  # active | strict | passive
MMF_TRUST_DEFAULT_LOA="Observer"  # Default access level
RUST_LOG="info,mmf_sigil=debug"  # Logging configuration
```

**TOML Configuration (`mmf.toml`):**
```toml
license_secret = "production_secret_key"
db_backend = "sled"

[irl]
enforcement_mode = "active"
threshold = 0.4
telemetry_enabled = false

[trust]
default_loa = "Observer"
allow_operator_canon_write = false
allow_admin_export = false
```

---

## 🚨 **Production Deployment Notes**

### **Security Checklist**
- [ ] Generate unique Ed25519 keys (never use defaults)
- [ ] Set strong `MMF_LICENSE_SECRET` environment variable
- [ ] Configure proper file permissions on key storage directories
- [ ] Enable audit logging with writable `logs/` directory
- [ ] Validate license files match runtime/canon fingerprints
- [ ] Test quorum operations with real mentor witnesses
- [ ] Configure rate limiting for your expected load

### **Operational Requirements**
- **Key Storage**: Secure filesystem with appropriate permissions
- **License Files**: Valid, signed licenses with correct LOA assignments
- **Log Directories**: `logs/` and `test_logs/` must be writable (fails closed otherwise)
- **Network**: HTTPS termination (this service provides HTTP only)
- **Backup**: Canon store encryption keys and signed witness registrations

---

## 📄 **License**

This codebase is governed by the **MMF License Framework**:

- **MMF-CL v1.1** ([Commercial License](MMF-CL_v1.1.md)) - For commercial use, deployment, and module commercialization
- **MMF-CUL v1.1** ([Community Use License](MMF-CUL_v1.1.md)) - For non-commercial use, extension, and redistribution
- **MMF-CLA v1.1** ([Contributor License Agreement](MMF-CLA_v1.1.md)) - Required for all contributions

### **Key License Requirements:**
- **Canon Structure Preservation**: Cannot bypass Canon structure, trust evaluation system, or LOA enforcement
- **Attribution Required**: Must include "Powered by the Sigil Protocol (Rule Zero enforced)"
- **Audit Traceability**: All derived systems must maintain Reasoning Chain compatibility
- **Trust Boundary Integrity**: Trust evaluation enforcement cannot be bypassed, suppressed, or falsified

### **Commercial Use:**
Commercial deployment requires MMF-CL compliance, including:
- Disclosure of Canon sources used
- Declaration of Canon divergence (if applicable)
- Retention of trust evaluation enforcement for memory/Canon operations
- Up-to-date `sigil_manifest.toml` with attribution

**This README reflects only implemented, tested functionality as of the current codebase state.**