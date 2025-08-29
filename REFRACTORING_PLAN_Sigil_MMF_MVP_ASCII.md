# Refactoring Plan -- Path to MVP

This plan turns the current prototype into a small, honest MVP that can be demoed and validated by tests. It is split into tracks with acceptance criteria and suggested sequencing. The MVP deliberately **excludes** IRL/distillation/ONNX and any complex MMF UI.

---

## MVP Definition (what "done" means)
- **Sigil runtime** exposes `/trust/check`, `/audit/{id}`, `/canon/user/write`, `/canon/system/{propose,attest}`.
- **Decisions** are produced by a **logistic trust model**, not keyword stubs.
- Every decision creates a `ReasoningChain`  `FrozenChain`; **FrozenChain is Ed25519signed** and **verifies** on read.
- **Systemspace commits** require kofn **witness signatures**; commits without quorum are blocked.
- **All Codex writes** stored as **CanonicalRecord v1** (canonicalized + hashed + signed).
- **E2E tests** cover: allow, deny, errordefaultdeny, tamperfail, quorumpass/fail, decryptonlist, module LOA gate.
- README and docs match reality; CI fails if claims lack passing tests.

---

## Track A -- Trust Evaluation (runtime correctness)

### A1. Replace keyword policy with logistic model
- **Work:** In `sigil_runtime_core`, construct `TrustFeatures` from the event (action, target, LOA, ratelimit window, input entropy). Load weights from config/Canon and evaluate via `TrustLinearModel`.- **Acceptance:** `/trust/check` returns `{score, allowed}` consistent with weights; tests assert high score for lowrisk ops and low score for risky ops.

### A2. Defaultdeny hardening
- **Work:** Audit all evaluator/storage fallbacks; ensure any error  `allowed=false`.- **Acceptance:** Faultinjection tests pass (forced evaluator error  403/deny).

---

## Track B -- Cryptographic audit (real integrity)

### B1. Sign `FrozenChain` with Ed25519
- **Work:** Add `signature: [u8;64]` and `public_key: [u8;32]` to `FrozenChain`. Sign `sha256( canonical(ReasoningChain-json) )` or the frozen content itself.- **Acceptance:** `verify_integrity()` returns true for untampered records and false after any byte flip (unit + e2e).

### B2. Canonicalization you can prove
- **Work:** Adopt JSON Canonicalization Scheme (JCS) or CBOR for cryptographic stability. Replace adhoc key sorting with a library or CBOR encoder.- **Acceptance:** Same logical record  same hash across runs and platforms (golden tests).

---

## Track C -- Canon / Codex Nexus (Rosetta Stone + quorum)

### C1. CanonicalRecord everywhere
- **Work:** Wrap all Codex writes in `CanonicalRecord v1` (kind/schema_version/id/tenant/ts/space/payload/links/prev/hash/sig/pub_key/witnesses). Validate presence and types.- **Acceptance:** `list_entries()` always returns valid canonical JSON; schema tests pass.

### C2. Enforce witness quorum on systemspace writes
- **Work:** Add `proposal:{id}` lifecycle; route `/canon/system/propose`  store proposal (unsigned). `/canon/system/attest`  verify witness sig against registry, append. Commit only when `signers.len() >= k`.- **Acceptance:** e2e quorum tests: k1 signatures  403; k signatures  commit; tamper with a signature  verify fails.

### C3. CDC emitter + projections (optional for MVP+1)
- **Work:** On commit, publish CanonicalRecord to a queue (NATS/Kafka/SQS). Provide reference consumers for Postgres (records + links tables) and Mongo/Dynamo (pk/gsis).- **Acceptance:** "Replay" test: drop projections, consume from offset=0  state matches golden.

---

## Track D -- Modules (make them real)

### D1. Execute a builtin module behind LOA
- **Work:** Move the sample "hello" module into a registry; on `/module/hello/run`, check LOA then call `run()`.- **Acceptance:** e2e: Operator LOA  200 with content; Guest  403.

### D2. Sandbox (MVP+1)
- **Work:** Run modules in a constrained process or WASM with capability injection; log stdout/stderr; enforce time/memory limits.- **Acceptance:** Timeouts and memory limits are enforced in tests.

---

## Track E -- Key management

### E1. Ed25519 key lifecycle
- **Work:** Generate, store (AESGCM), and rotate signing keys. Document env/config controls.- **Acceptance:** Rotation test creates new keys and continues to verify both new and historical records.

### E2. Witness registry
- **Work:** Manage trusted witness public keys (add/remove/list). Persist in Canon system space.- **Acceptance:** Only registered witnesses can attest proposals; others rejected with tests.

---

## Track F -- Tests & CI

### F1. E2E tests
- **Tests:**
  - `e2e_allow`
  - `e2e_deny`
  - `e2e_error_default_deny`
  - `e2e_tamper_audit`
  - `e2e_quorum_pass_fail`
  - `e2e_canon_iter_decrypt`
  - `e2e_module_gate`

**Acceptance:** All pass in CI.

### F2. Docs enforcement
- **Work:** Add a "claims map" (TOML) linking README claims to tests/symbols; CI fails if a claim's proof is missing.- **Acceptance:** PRs that change README without proofs are blocked.

---

## Suggested sequencing (10-14 focused days)

**Days 1-2**: A1/A2 (logistic model wiring + deny hardening)  
**Days 3-4**: B1/B2 (FrozenChain Ed25519 + canonicalization)  
**Days 5-6**: C1/C2 (CanonicalRecord everywhere + quorum enforcement)  
**Day 7**    : D1 (module execution)  
**Day 8**    : F1 initial e2e tests (allow/deny/tamper/quorum)  
**Day 9**    : E1/E2 (key lifecycle + witness registry)  
**Days 10-12**: C3 optional CDC + projections  
**Days 13-14**: F2 docs enforcement + polish

---

## Risks & mitigations
- **Spec drift:** Use CanonicalRecord + JCS/CBOR + tests to lock the contract.
- **Crypto misuse:** Prefer wellreviewed libs; keep keys out of process memory when possible.
- **Complexity creep:** IRL/distillation remain explicitly out of MVP scope.
- **Security regressions:** Keep defaultdeny. Fuzz parsers and validate JSON schemas.
