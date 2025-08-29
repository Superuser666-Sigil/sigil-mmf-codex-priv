# Sigil / MMF / Codex Nexus -- Honest README (Prototype)

This repository is a **prototype** of a threelayer system:

- **Sigil (runtime kernel)** -- enforces Levels of Access (LOA), validates requests, evaluates trust, records signed audits, and mediates all access to Canon/Codex.
- **Codex Nexus (Canon datastore)** -- encrypted KV store for audit records (FrozenChains), user/session memories, and operatorprovided RAG documents.
- **MMF (interaction layer)** -- thin UI/API that *must* call Sigil; it does not touch Codex directly.

> This README reflects the **actual** current state of the code, not the original vision doc. Features are grouped as Implemented / Partial / Not Implemented so you can plan realistically.

---

## Current status (truthful)

###  Implemented
- **Encrypted Canon storage (Sled + AESGCM)**  
  All values written encrypted; `list_entries()` now decrypts before deserializing to JSON (fixes prior integrity bug).
- **Defaultdeny security posture**  
  Trust evaluation failures return a deny instead of allowing by default.
- **Ed25519 signatures for _ReasoningChain_**  
  Reasoning chains are hashed (SHA256) and signed with Ed25519; verification rehashes and verifies the signature.
- **Quorum framework (systemspace writes)**  
  A `SystemProposal` type, witness registry scaffolding, and signature collection logic exist (kofn threshold).
- **Module trait + LOA requirement (scaffold)**  
  A `SigilModule` trait with `required_loa()` / `run()` exists and a simple example module is defined.

###  Partial / Prototype
- **FrozenChain integrity**  
  Currently still stores a toy `"sig_<16 chars of hash>"` signature. The chain **does not** yet carry Ed25519 signatures endtoend. Integrity checks recompute content/Merkle hashes but skip real signature verification.
- **Trust model**  
  A real 5feature **logistic model** exists (`trust_linear.rs`) with tests, but **is not wired into the runtime**; the runtime still uses a simple keyword policy in places or a stub evaluator.
- **Witness quorum enforcement**  
  Proposal/signature collection is present, but commits don't yet *require* verified witness signatures endtoend (no blocking checks in audit/canon commit paths).
- **Module runtime**  
  Manifests are parsed and logged; the sample module is not actually loaded/executed from the runtime entrypoints.

###  Not Implemented
- **Inverse Reinforcement Learning (IRL)**, **knowledge distillation**, **ONNX import/export** -- not present beyond placeholders/stubs.
- **Real CDC / projections** to SQL/NoSQL; no queue/topic emitting canonical records for downstream projections.
- **Full web UI / MMF** -- only thin HTTP stubs; no production UI.

---

## Architecture at a glance

```
MMF (UI) HTTP> Sigil (runtime) > Canon/Codex (encrypted KV)
                          
                           Trust model (planned: logistic  IRL later)
                           Audit: ReasoningChain  FrozenChain (signed)
                           Quorum: kofn witnesses for systemspace
```

- **All nontrivial operations must be mediated by Sigil.**  
  MMF never writes Codex directly.
- **Appendonly audit mindset.**  
  Mutations produce new versions; deletes are tombstones.

---

## Canonical "Rosetta Stone" JSON (what downstreams map from)

> The project includes a `CanonicalRecord` type (see `src/canonical_record.rs`) intended as the single, portable schema emitted for every committed object. This is the basis for projecting into SQL/NoSQL/search engines.

**Fields (v1):**
```json
{
  "kind": "frozen_chain | memory_block | rag_doc",
  "schema_version": 1,
  "id": "ULID/UUID",
  "tenant": "org-or-user",
  "ts": "RFC3339",
  "space": "user | system",
  "payload": { "...type-specific..." },
  "links": [{ "rel": "parent", "id": "..." }],
  "prev": "id-or-null",
  "hash": "sha256(canonical-plaintext)",
  "sig": "ed25519(base64)",
  "pub_key": "ed25519-pk(base64)",
  "witnesses": [{ "id": "w1", "sig": "..." }]
}
```

**Canonicalization:** JSON keys are deterministically ordered before hashing/signing to ensure stable verification. (Production should adopt JCS or switch to CBOR for cryptographic canonicalization.)

---

## Running (prototype)

```bash
# Build & test
cargo build
cargo test

# Run (example binary if provided)
cargo run
```

> Expect stub outputs in several paths. The system is **not** productionsafe yet.

---

## Security notes (read before demoing)

- **Do not** claim endtoend tamperevident audits until `FrozenChain` is signed/verified with Ed25519.
- **Do not** claim IRL/distillation/ONNX support. These are not implemented.
- Keep **defaultdeny** behavior intact; errors must not produce "allowed=true."

---

## Roadmap (high level)

1. Wire logistic trust model into Sigil runtime; remove keyword stub.
2. Propagate Ed25519 signatures to `FrozenChain`; verify on read.
3. Enforce witness quorum in commit paths.
4. Adopt JCS/CBOR for canonicalization; emit CanonicalRecord for all writes.
5. Add CDC emitter + SQL/NoSQL mappers; replay to rebuild projections.
6. Execute at least one real module behind LOA; sandbox and log output.
7. E2E test suite covering allow/deny, tamper, quorum, and projections.
8. Honest README stays synchronized with tests; CI blocks unverifiable claims.

---

## License / policy
See repository license files. This README deliberately avoids aspirational claims; only tested, verifiable behavior is listed here.
