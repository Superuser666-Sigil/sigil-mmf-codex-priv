# SigilDERG/MMF/Codex Nexus Refactoring Plan (MVP Readiness)

## Context and Vision
Sigil provides a secure local runtime for large-language-model agents. Three cooperating subsystems form the architecture:
- MMF (module execution layer) hosts user-facing modules and enforces Rule Zero outputs.
- SigilDERG (control plane) applies trust policies, LOA gates, quorum logic, and routes requests.
- Codex Nexus (data plane) stores canonicalized, hashed, and signed records for durable audit and RAG.

## MVP Goals Recap
1. Unified encrypted canonical storage; every persistent write must be canonicalized, hashed, and signed.
2. End-to-end LOA enforcement and license validation, including quorum-controlled system writes.
3. Functional memory and RAG APIs with auditable persistence.
4. Complete CLI and API surface for licenses, witnesses, proposals, module execution, and data management.
5. Comprehensive tests, documentation, and tooling that keep the runtime trustworthy.

## Status Overview
### Completed Components
- Ed25519 key management, signing, and verification.
- AES-GCM sled-backed CanonStore (encrypted) plus deterministic test-only key helper.
- JSON Canonicalization (RFC 8785) with updated fixtures and PI constants.
- CSRF protection (read-lock validation, post-success invalidation, periodic cleanup).
- Rate limiting with background maintenance task.
- HTTP APIs covering trust, canon operations, proposals, attestation, module execution.
- CLI utilities (runtime launcher, web server, canon validation, key lifecycle, license generator with error propagation).
- Audit & trust pipeline (ReasoningChain + FrozenChain, witness registry, SigilRuntimeCore gating).
- Sign-on-write now default across API, module, and quorum paths.

### Partially Complete Areas (updated)
- Canon storage still has legacy unencrypted helpers in tests and lacks migration tooling.
- License validation works, but LOA policies remain scattered and development header fallback is enabled by config.
- Witness/quorum flow revalidates signatures but lacks rotation, revocation, and rich CLI management.
- Memory/RAG APIs persist signed records but miss pagination, vector-store integration, and provenance tooling.
- Module integration persists FrozenChains yet lacks ModuleContext helpers and Rule-Zero manifest enforcement.
- Configuration/glue code still constructs state ad-hoc; needs harmonized config loader.
- CLI/tooling roadmap largely outstanding beyond existing utilities.
- Quality gates exist in CI, but stress, concurrency, failure-injection, and performance suites are absent.

## Detailed Refactoring Tasks

### 1. Consolidate Canon Storage
**Status:** In Progress

**Current Reality**
- Encrypted `CanonStoreSled` is production default.
- All tests now instantiate the encrypted variant via `EncryptedCanonStoreSled::new` using `KeyManager::dev_key_for_testing()`.
- No migration utilities exist for legacy unsigned records.

**Next Actions**
- Provide a `CanonStore` trait backed solely by the encrypted sled implementation; deprecate unencrypted helpers except in hermetic tests.
- Deprecate or feature-gate the unencrypted `canon_store_sled` module and forbid production usage.
- Build a migration tool that canonicalizes, hashes, and re-signs legacy/test records.
- Exercise sled transactions under load (concurrency harness + crash-recovery).
- Document operational runbooks for key rotation, backup, and restore.

**Acceptance Criteria**
- One production storage backend (encrypted) with verified migrations.
- Concurrency/crash tests demonstrate atomicity.
- Operational docs cover key and store management.

### 2. Enforce Sign-on-Write Everywhere
**Status:** Complete (Follow-up Hardening)

**What Changed**
- All API, module, and quorum writes emit signed `CanonicalRecord`s.
- `KeyManager::get_encryption_key` now errors when the secret is missing; tests opt into `install_dev_encryption_key_for_testing`.

**Remaining Work**
- Add failure-injection tests (signature failure, canonicalization error, storage refusal).
- Build stress tests with concurrent writers to smoke out lock/IO contention.
- Trace logging of sign/write results for audit correlation.

### 3. Implement License Validation and LOA Enforcement
**Status:** Partially Complete (Middleware integrated for enhanced routes)

**Current Reality**
- License validator verifies signed documents via headers or cookies.
- Handlers fall back to development header auth when `MMF_DEV_HEADER_AUTH` is enabled.
- LOA requirements are enforced inline by each route.
 - Central LOA policy table and middleware added for `enhanced_web` routes.
 - Dev header fallback now additionally gated by compile-time feature `dev-auth`.

**Next Actions**
- Centralize LOA policy mapping (per route/CLI command) and remove inline duplication.
- Extend middleware to legacy `sigilweb` router (needs bindings access) or migrate remaining routes to `enhanced_web`.
- Gate the dev fallback behind explicit build/runtime toggles with loud warnings. (Feature `dev-auth` + `MMF_DEV_HEADER_AUTH` env)
- Expand negative tests (expired, malformed, mismatched runtime/LOA).

**Acceptance Criteria**
- All ingress paths share a single policy table and middleware (or are migrated to `enhanced_web`).
- CI tests cover LOA success/failure matrices.
- Development bypass requires explicit opt-in and cannot leak to production.

### 4. Complete Witness/Quorum System
**Status:** Partially Complete

**Current Reality**
- System proposal commits revalidate signatures and persist signed records.
- Witness registry now exposes poison-aware reads but lacks rotation and revocation.

**Next Actions**
- Implement witness key rotation, revocation, and listing APIs/CLI commands.
- Enforce k-of-n uniqueness with clearer error feedback (duplicates, stale proposals, wrong hashes).
- Add tests for expiration logic and prev-hash validation.

**Acceptance Criteria**
- Rotation and revocation flows exist with integration tests.
- Quorum rejection cases are exhaustively tested.
- Ops tooling emits structured logs/metrics for proposal lifecycle.

### 5. Finalize Memory and RAG APIs
**Status:** Partially Complete

**Current Reality**
- `memory_write`, `memory_list`, and `rag_upsert` emit signed canonical records.
- No pagination, filtering, or vector-store integration is present.
- Ingestion/licensing pipeline is still conceptual.

**Next Actions**
- Add pagination and LOA-aware filtering to listing endpoints.
- Integrate vector storage (e.g., hnswlib/FAISS) or stub interface with tests.
- Build provenance/licensing checks for ingestion, plus CLI import helpers.

**Acceptance Criteria**
- APIs support filtered, paginated reads and concurrent writes.
- Vector-store integration has tests and metrics.
- Data ingestion validates source licenses and records provenance.

### 6. Integrate Trust Evaluation with SigilDERG
**Status:** Mostly Complete (Policy Work Remains)

**Current Reality**
- `SigilRuntimeCore::validate_action` returns `SigilResult` and handlers gate on trust decisions.

**Next Actions**
- Implement trust score decay/recovery and model weight updates.
- Feed trust outcomes into witness/quorum prioritization and module run policies.
- Record trust decisions to audit trails for later review.

**Acceptance Criteria**
- Policy changes reflected in config/tests (e.g., thresholds per operation).
- Trust history stored for analytics/audit.
- Quorum and module systems consume trust-derived signals.

### 7. Integrate Modules with Canonical Storage
**Status:** Partially Complete

**Current Reality**
- RustMentor persists FrozenChain records to CanonStore.
- ModuleContext abstraction and Rule-Zero manifest enforcement are not implemented.

**Next Actions**
- Provide ModuleContext helpers (write_memory, log_interaction, emit_audit) that encapsulate canonicalization.
- Enforce Rule-Zero manifest validation on module outputs with tests.
- Document module authoring guide and CLI scaffolding.

**Acceptance Criteria**
- Modules interact exclusively through ModuleContext helpers.
- Manifest validation stops incomplete or malformed responses.
- Developer documentation and examples are published.

### 8. Clean Up Runtime Glue and Configuration
**Status:** Partially Complete

**Next Actions**
- Harmonize config keys across TOML, env vars, and CLI flags.
- Build a single loader that merges defaults, files, and env overrides with validation.
- Construct `AppState` exclusively through validated config and inject shared services.
- Consolidate routing/middleware in `enhanced_web` and deprecate legacy paths.

### 9. Expand CLI and Developer Tooling
**Status:** Partially Complete

**Next Actions**
- Implement `sigil-cli` commands for key generation, witness management, proposals, memory/RAG import, and module test harnessing.
- Provide a `make dev` or cargo xtask to bootstrap a dev environment with sample keys and data.
- Ensure CLI paths reuse the same canonicalization/LOA checks as the HTTP API.

### 10. Testing and Quality Assurance
**Status:** Incomplete

**Next Actions**
- Build canonicalization cross-checks against a reference implementation.
- Add sign/verify mutation tests to ensure tampering detection.
- Extend LOA, quorum, and module tests to cover failure scenarios.
- Create concurrency, load, and performance suites plus `cargo miri` smoke tests for hot paths.
- Establish documentation linting and threat-model validation.

## Additional Follow-ups
- Add guardrails around `install_dev_encryption_key_for_testing` to prevent accidental production use (lint/config check).
- Optimize rate-limiter cleanup so multiple routers do not spawn duplicate tasks in a single process.
- Track documentation debt (API reference, ops runbooks, security model) alongside code tasks.

## Critical Path (Updated)
1. Finish storage consolidation and migration tooling. (tests migrated to encrypted store)
2. Centralize LOA/Trust policies and remove dev bypass from production builds. (Active focus)
3. Complete witness rotation/revocation plus quorum edge cases.
4. Deliver memory/RAG pagination + vector integration + provenance pipeline.
5. Ship ModuleContext helpers and Rule-Zero enforcement.
6. Harden testing with concurrency, failure-injection, and performance suites.

## CI Pipeline Summary
- `cargo fmt`, `cargo clippy -D warnings`, `cargo test --all-features`, `cargo doc -D warnings` run on every PR (windows + linux matrix).
- Security checks: `cargo audit`, `cargo deny`, minimal-versions build, outdated dependency report, SBOM generation.
- Future work: add stress-test and miri jobs once harnesses exist.

## Conclusion
Foundational security features (sign-on-write, CSRF, trust gating, deterministic key handling) are now in place. The remaining roadmap focuses on operational maturity: unified storage, rigorous license/LOA policies, full quorum tooling, production-ready memory/RAG pipelines, module ergonomics, and exhaustive testing/documentation. Delivering these items will move Sigil from a robust prototype to a production-grade secure runtime for local LLM workloads.
