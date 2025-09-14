# SigilDERG/MMF/Codex Nexus – Refactoring Plan to Achieve Strong MVP

## Context and Vision
The Sigil project aims to provide a secure local runtime for large‑language‑model agents and modules. Its distinctive features are a logistic trust model with levels of access (LOA), cryptographically verifiable audit trails using JSON Canonicalization Scheme (JCS), SHA‑256 hashing and Ed25519 signatures, and a k‑of‑n witness quorum for privileged operations. Three subsystems define the architecture:
•	MMF (Sigil module execution layer) – hosts user‑facing modules and manages interactions; modules must return structured outputs according to Rule Zero.
•	SigilDERG (control plane) – enforces trust policies, LOA gates, witness/quorum logic, and routes requests to the correct components.
•	Codex Nexus (data plane) – stores canonicalized, signed records and supports retrieval and retrieval‑augmented generation.

## High‑Level Goals for MVP
1.	Unified, encrypted storage backend for all canonical records; every persistent write must be canonicalized, hashed and signed.
2.	Full LOA and trust enforcement, including license validation and k‑of‑n witness gating on system‑space writes.
3.	Functional memory and RAG APIs so modules can persist outputs and support retrieval‑augmented generation.
4.	Complete CLI and API interfaces for licenses, witnesses, proposals, commits, module invocation and data management.
5.	Comprehensive tests, documentation and tooling to ensure correctness and maintainability.

## Current Implementation Status
✅ **COMPLETED COMPONENTS:**
- Ed25519 Cryptographic Signatures: Complete implementation with key generation, signing, and verification
- Encrypted Canon Storage: AES-GCM encrypted Sled database backend with secure key management  
- JSON Canonicalization (RFC 8785): Cryptographically stable JSON representation for tamper-evident records
- CSRF Protection: Token-based protection with configurable expiration
- Rate Limiting: Configurable request throttling per client
- HTTP API: Basic trust evaluation, canon operations, system proposals, module execution endpoints
- CLI Tools: Runtime execution, web server, canon validation, key management, license generation
- Audit & Trust System: ReasoningChain → FrozenChain, audit chain integrity, witness registry

🔄 **PARTIALLY COMPLETE:**
- Trust Evaluation System: Logistic trust model with 5-feature evaluation exists but isn't driving gating decisions or weight updates
- LOA (Level of Access) Enforcement: 5-tier access control system exists but license validator and middleware don't actually gate requests
- Quorum System: Multi-party witness signatures scaffolding exists but validation logic has significant gaps
- License System: Basic structure exists but validation and LOA enforcement are stubs
- Memory/RAG APIs: Endpoints exist but use minimal test records, not fully signed
- Module System: Basic structure exists but integration with canonical storage is incomplete
- Configuration: Basic TOML config exists but needs harmonization across components

❌ **INCOMPLETE:**
- Sign-on-write enforcement everywhere
- Complete witness/quorum system with proper validation
- Full memory/RAG functionality with vector storage
- Module integration with canonical storage
- Comprehensive testing and documentation
- Legacy record migration to signed format

## Detailed Refactoring Tasks

### 1. Consolidate Canon Storage
**Status: PARTIALLY COMPLETE** - Encrypted sled backend exists but multiple backends remain

**Tasks:**
- Adopt one production canonical storage backend using encrypted sled; remove file‑based or unencrypted back‑ends
- Provide a CanonStore trait with a concrete SledCanonStore using the existing encryption key and path
- Supply migration scripts to convert existing records
- **Legacy Record Migration**: Create migration utilities to convert unsigned or "test" records currently in Canon to the new signed format
- Ensure the store is an append‑only log of CanonicalRecord objects
- Each record must be canonicalized with JCS, hashed using SHA‑256 and signed with Ed25519
- Current API handlers often use CanonicalRecord::new_minimal_for_test and bypass signatures; replace these with fully signed records on every write
- Expose simple CRUD operations via the CanonStore trait: add_record, get_record, list_records and retrieval by prev hash
- Use sled transactions to guarantee atomic writes and implement crash‑recovery tests

**Acceptance Criteria:**
- All writes to CanonStore verified in tests with proper JCS canonicalization and Ed25519 signatures
- Migration scripts successfully convert all existing test records to signed format
- Sled transaction model tested under concurrent writes to uncover race conditions
- Crash-recovery tests demonstrate atomic writes and data integrity

### 2. Enforce Sign‑on‑Write Everywhere
**Status: INCOMPLETE** - Many write paths still use minimal, unsigned test records

**Tasks:**
- Review all API handlers and internal functions that produce persistent data (license issuance, proposals, system commits, memory/RAG entries, module results, configuration changes) and ensure each performs:
  - Deterministic JCS serialization of the payload
  - SHA‑256 digest of the canonical string
  - Ed25519 signature via the runtime KeyStore
  - Construction of a CanonicalRecord with metadata (kind, space, schema_version, links, prev etc.)
  - Persistence to CanonStore
- Replace TODOs in the memory API and module code where writes are currently stubbed or logged
- Update commit_system_proposal so it appends the canonical record to the store instead of simply logging the operation
- Add an audit hook to capture success/failure for each write and ensure logs cannot be suppressed
- **Concurrency Testing**: Exercise signature code paths under concurrent writes to uncover race conditions
- **Error Handling**: Test signature failures, canonicalization errors, and storage failures under various conditions

**Acceptance Criteria:**
- Every persistent write path produces a properly signed CanonicalRecord
- No more CanonicalRecord::new_minimal_for_test usage in production code paths
- Concurrency tests pass with multiple simultaneous writes
- Error handling gracefully manages signature failures and storage errors

### 3. Implement License Validation and LOA Enforcement
**Status: PARTIALLY COMPLETE** - Basic structure exists but validation and LOA enforcement are stubs

**Tasks:**
- Finalize the license document schema: include subject ID, issue time, expiry, permitted LOA and role (root/operator/mentor/observer/guest)
- Canonicalize and sign licenses using the root key
- In the auth middleware, validate incoming licenses by canonicalizing the document, computing the hash, verifying the signature and checking the expiry
- Extract LOA and role and attach them to the request context
- Replace the stubbed /api/license/validate endpoint with a real service that verifies uploaded licenses and returns the caller's LOA and role
- Map each API route and CLI command to a required LOA; e.g., memory writes require Mentor LOA, system‑space commits require root LOA plus k‑of‑n witnesses
- Implement a policy layer so enforcement is consistent

**Acceptance Criteria:**
- License validator and middleware actually gate requests based on LOA
- All API endpoints reject requests with insufficient LOA
- License validation tests cover expired, invalid, and malformed licenses
- LOA enforcement is consistent across all API routes and CLI commands

### 4. Complete Witness/Quorum System
**Status: PARTIALLY COMPLETE** - Basic quorum system exists but needs refinement

**Tasks:**
- Extend the witness registry to support key rotation, revocation and listing
- Provide CLI commands to manage witnesses
- Refine quorum logic so proposals have unique IDs, and witness signatures are stored in the witnesses field
- commit_system_proposal must verify k‑of‑n unique signatures, ensure the prev pointer references the latest system record, validate canonicalization and root signature, and then append the record to the canon store
- Add tests for invalid witness lists (duplicate IDs, insufficient signatures, wrong hashes or expired proposals)

**Acceptance Criteria:**
- Quorum validation logic properly verifies k‑of‑n unique signatures
- System proposals cannot be committed without sufficient witness signatures
- Witness registry supports key rotation and revocation
- All quorum edge cases (duplicates, insufficient signatures, invalid hashes) are properly handled

### 5. Finalize Memory and RAG APIs
**Status: PARTIALLY COMPLETE** - Endpoints exist but use minimal test records, not fully signed

**Tasks:**
- Complete memory_write: accept key, text, ts and user_id, validate LOA, canonicalize and sign the payload, and persist it as a CanonicalRecord in the data space
- Implement memory_list with pagination and LOA checks; allow retrieval of memory entries by key or by time range
- Implement rag_upsert: accept content and embeddings, persist the vector into a vector store (hnswlib/FAISS) keyed by key, and wrap metadata in a signed canonical record
- **Data Hygiene Pipeline**: Create formal data-ingestion pipeline with provenance and license checks for RAG corpus
- **RAG Corpus Management**: Implement license validation and provenance tracking for Rust docs, crates, and other ingested data
- Provide CLI tools to import RAG datasets (e.g., Rust docs) and persist them via the API

**Acceptance Criteria:**
- Memory and RAG APIs produce fully signed CanonicalRecords
- Memory entries are properly paginated and filtered by LOA
- Vector store integration works with concurrent writes
- Data ingestion pipeline validates licenses and tracks provenance
- CLI tools successfully import and persist RAG datasets with proper licensing metadata

### 6. Integrate Trust Evaluation with SigilDERG
**Status: PARTIALLY COMPLETE** - Trust evaluation system exists but isn't driving gating decisions

**Tasks:**
- Wire trust evaluation system through SigilDERG control plane to drive gating decisions
- Implement trust score-based weight updates and policy enforcement
- Integrate trust evaluation with module execution and LOA enforcement
- Add trust score thresholds for different operations and modules
- Implement trust score decay and recovery mechanisms
- Add trust evaluation to quorum decisions and witness selection

**Acceptance Criteria:**
- Trust evaluation system drives actual gating decisions in SigilDERG
- Trust scores influence module execution and LOA enforcement
- Trust-based weight updates are implemented and tested
- Trust evaluation integrates with quorum and witness systems

### 7. Integrate Modules with Canonical Storage
**Status: PARTIALLY COMPLETE** - Basic module system exists but integration with canonical storage is incomplete

**Tasks:**
- Ensure RustMentorModule writes its reasoning chain and suggestion to the canon store; currently it logs but does not persist
- Provide a ModuleContext to modules with canon_store, trust_evaluator, license and rag_store handles
- Implement helper methods like write_memory() and log_interaction() to hide canonicalization details
- Document and enforce the Rule Zero module manifest (fields: input, context, reasoning, suggestion, verdict, audit)
- Reject modules that do not return complete records

**Acceptance Criteria:**
- Module outputs persisted with full Rule‑Zero manifest
- RustMentorModule produces signed canonical records for all interactions
- ModuleContext provides clean abstraction for canonicalization
- All modules enforce complete Rule Zero manifest requirements

### 8. Clean Up Runtime Glue and Configuration
**Status: PARTIALLY COMPLETE** - Basic TOML config exists but needs harmonization

**Tasks:**
- Harmonize configuration keys across environment variables, command‑line flags and config files
- Create a single config.toml with namespaced sections (canon, keystore, server, llm, policies)
- Provide a config module that loads defaults, merges environment overrides and validates required fields
- Construct AppState from validated config and pass Arc<dyn CanonStore> and KeyStore to all components
- Remove deprecated routes from the old sigilweb router and centralize middleware in enhanced_web

### 9. Expand CLI and Developer Tooling
**Status: PARTIALLY COMPLETE** - Basic CLI exists but needs expansion

**Tasks:**
- Develop a sigil-cli with commands for:
  - Generating root and witness keys
  - Creating and signing licenses
  - Registering and listing witnesses
  - Creating proposals, collecting witness signatures and committing them
  - Importing memory and RAG data
  - Running modules for testing
- Ensure CLI commands invoke the same canonicalization and LOA checks as the API
- Provide a make dev script to spin up a development environment with sample keys, a test canon store and seed memory/RAG data from permissively licensed Rust documentation

### 10. Testing and Quality Assurance
**Status: INCOMPLETE** - Basic tests exist but comprehensive coverage needed

**Tasks:**
- Canonicalization tests: create a suite of JSON structures and confirm that JCS serialization matches RFC 8785; cross‑check with a reference implementation
- Sign/verify tests: verify that all record writes produce valid signatures; mutate payloads and signatures to ensure verification fails
- LOA enforcement tests: confirm that unauthorized LOA values are rejected and valid LOA values succeed for each endpoint
- Quorum tests: test k‑of‑n witness logic with duplicate signatures, insufficient signers and invalid hashes
- Memory/RAG tests: test writing, listing and retrieving memory blocks; run concurrent writes to ensure order and consistency
- Module integration tests: run the RustMentorModule end‑to‑end; verify it produces signed canonical records and respects trust policies
- **Concurrency and Error‑Handling Tests**: Exercise sled's transaction model and signature code paths under concurrent writes to uncover race conditions
- **Performance Testing**: Measure overhead of signing, verification and k‑of‑n quorum under load; implement batch signing or caching if needed to keep latency acceptable
- Use property‑based testing (e.g., proptest) for canonicalization and signature invariants; run miri to detect undefined behaviour and concurrency issues
- Enforce clippy, fmt, audit and deny in continuous integration

**Acceptance Criteria:**
- All tests pass under concurrent execution
- Race conditions in signature and storage code paths are eliminated
- Performance tests show acceptable latency for signing, verification, and quorum operations
- Property-based tests validate canonicalization and signature invariants
- Miri reports no undefined behavior
- CI pipeline enforces all quality gates (clippy, fmt, audit, deny)

### 11. Documentation and Research Artifacts
**Status: INCOMPLETE** - Basic README exists but comprehensive documentation needed

**Tasks:**
- Update REFRACTORING_PLAN to track progress on the tasks listed here; remove completed items
- Revise the README to describe the architecture, trust model, LOA hierarchy, witness/quorum design and setup instructions
- Publish an API specification (OpenAPI/Swagger) documenting endpoints, request/response formats and LOA requirements
- Write a CLI guide and a module developer guide detailing how to implement Rule Zero modules and interact with the canon store
- Provide a system administrator guide covering key setup, witness management, storage configuration and seeding RAG data
- Include a threat model and security analysis explaining why canonicalization, signatures and quorum are necessary and what threats remain

### 12. Licensing and Packaging
**Status: PARTIALLY COMPLETE** - License files exist but needs clarification

**Tasks:**
- Clarify project licensing and embed license notices in all source files
- Document licenses for imported datasets (e.g., The Rust Book, Rustonomicon) and store this metadata in the canon store
- Provide a root LICENSE file and update Cargo.toml metadata
- Package the runtime as a container image with minimal dependencies; include sample keys and configuration for quick start
- Provide Docker Compose or Nix definitions for running the full stack

### 13. Future Directions Beyond MVP
**Status: NOT APPLICABLE** - Future enhancements

**Tasks:**
- Explore threshold signatures (e.g., FROST for Ed25519) so multiple witness signatures can be aggregated into a single signature
- Integrate a public transparency log (e.g., Sigstore Rekor) to mirror record digests for independent verification
- Add multi‑tenant support with per‑tenant witness sets and namespaced canon stores
- Investigate hardware‑backed key storage and remote attestation for runtime integrity
- Develop additional modules and a plugin ecosystem, using WASI sandboxing to run untrusted module code

## Critical Path and Prioritization

### Phase 1: Core Security Foundation (Weeks 1-2)
**Critical Path Tasks:**
1. **Enforce Sign‑on‑Write Everywhere** - Foundation for all other security
2. **Implement License Validation and LOA Enforcement** - Required for access control
3. **Consolidate Canon Storage** - Unified storage with proper signing

### Phase 2: Trust and Control (Weeks 3-4)
**Critical Path Tasks:**
4. **Integrate Trust Evaluation with SigilDERG** - Wire trust system into control plane
5. **Complete Witness/Quorum System** - Multi-party validation for system changes

### Phase 3: Data and Modules (Weeks 5-6)
**Critical Path Tasks:**
6. **Finalize Memory and RAG APIs** - Data persistence with proper signing
7. **Integrate Modules with Canonical Storage** - Module outputs properly persisted

### Phase 4: Polish and Production (Weeks 7-8)
**Supporting Tasks:**
8. **Clean Up Runtime Glue and Configuration** - Production readiness
9. **Testing and Quality Assurance** - Comprehensive validation
10. **Documentation and Research Artifacts** - User and developer guides

**Timeline Notes:**
- Focus on critical path tasks first to ensure MVP functionality
- Performance testing should be integrated throughout, not left until the end
- Data hygiene pipeline can be developed in parallel with RAG APIs
- CLI tooling can be developed incrementally as other systems mature

## CI Pipeline and Quality Gates

### Continuous Integration Requirements
- **Code Quality**: `cargo clippy --all-targets --all-features -- -D warnings`
- **Formatting**: `cargo fmt --all -- --check`
- **Security Audit**: `cargo audit` (if configured)
- **License Check**: `cargo deny check` (if configured)
- **Testing**: `cargo test --workspace --all-features`
- **Documentation**: `cargo doc --workspace --no-deps -D warnings`
- **Concurrency Testing**: Run tests with `RUST_TEST_THREADS=1` and `RUST_TEST_THREADS=16`
- **Memory Safety**: `cargo miri test` for critical paths

### MVP Acceptance Criteria Checkpoint
Each major task includes specific acceptance criteria that must be met before considering the MVP complete:

1. **Storage Consolidation**: All writes verified with proper signatures, migration complete
2. **Sign-on-Write**: No test records in production, concurrency tests pass
3. **LOA Enforcement**: License validator actually gates requests, all endpoints protected
4. **Quorum System**: k‑of‑n validation works, edge cases handled
5. **Memory/RAG**: Fully signed records, vector store integration, data hygiene pipeline
6. **Trust Integration**: Trust evaluation drives gating decisions in SigilDERG
7. **Module Integration**: Rule Zero manifest enforced, outputs persisted
8. **Configuration**: Harmonized across components, validated at startup
9. **CLI Tooling**: Complete command set with proper LOA checks
10. **Testing**: Comprehensive coverage including concurrency, error handling, and performance
11. **Documentation**: Complete API spec, guides, and threat model

### CI Pipeline Configuration
```yaml
# .github/workflows/ci.yml (example)
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          components: rustfmt, clippy
      - name: Run tests
        run: cargo test --workspace --all-features
      - name: Run clippy
        run: cargo clippy --all-targets --all-features -- -D warnings
      - name: Check formatting
        run: cargo fmt --all -- --check
      - name: Run miri (if available)
        run: cargo miri test --workspace
```

## Conclusion
The current codebase lays a solid foundation by introducing key systems such as license issuance, memory APIs, a sample module, enhanced routing and cryptographic key management. However, it still falls short of a strong MVP: persistent writes are not yet signed or stored, multiple canon back‑ends remain, LOA enforcement and license validation are stubs, and memory and RAG functionality is incomplete. By executing this refactoring plan—consolidating storage, enforcing sign‑on‑write, completing the witness/quorum system, finishing memory/RAG APIs, integrating modules with the data layer, cleaning up configuration, expanding tooling and adding comprehensive tests and documentation—the Sigil project will reach a robust, auditable and extensible MVP that realises the unique vision of secure, trustworthy and self‑governing local LLM execution.
