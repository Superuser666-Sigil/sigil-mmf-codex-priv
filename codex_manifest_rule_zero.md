## Sigil Module Manifest — Rule Zero (Immutable Trust Foundation)

### Module Name: Sigil Mentor (v2)
### Status: Core Required
### Enforcement: Yes (Sigil Trusted Module)

---

## Reasoning Chain Compliance (REQUIRED)

Every trusted module MUST emit a JSON object compatible with `ReasoningChain` (see `src/audit_chain.rs`). Minimal required shape:

```json
{
  "input": "Raw user input",
  "context": "Resolved canonical context",
  "reasoning": "Concise, checkable explanation",
  "suggestion": "Proposed action/output",
  "verdict": "Allow|Deny|Defer|ManualReview",
  "audit": {
    "timestamp": "RFC3339",
    "session_id": "uuid",
    "loa": "Guest|Observer|Operator|Mentor|Root",
    "chain_id": "uuid"
  },
  "trust": {
    "model_id": "logistic_trust_v1",
    "score": 0.0,
    "allowed": false
  },
  "scope": {
    "user_id": "string",
    "module_id": "string",
    "session_id": "string"
  },
  "witnesses": [
    { "witness_id": "string", "signature": "base64" }
  ]
}
```

Integrity extensions (when signing a reasoning chain):
- `content_hash` (hex SHA-256 over content)
- `signature` (base64 Ed25519)
- `public_key` (base64 Ed25519)

Frozen record requirements (when converting to `FrozenChain`):
- Content hash, Merkle root, optional Ed25519 signature must verify.
- Snapshots of input/reasoning/output/metadata must be consistent.

### Violations of this structure result in:
- API access revocation for the emitting module
- LOA lock escalation requirement (manual review by `LOA::Root`)
- Canon write disabled (no mutation privileges)
- Exclusion from training datasets (frozen chains rejected)

---

## Scope

- Language Support: Rust-first (Python/TypeScript/Bash tooling allowed)
- Trust Enforcement: Enabled by default
- Canon Mutation: permitted only when ALL are true:
  - `verdict == Allow`
  - `trust.allowed == true`
  - Witness quorum satisfied (≥ 3) per `ReasoningChain::finalize_reasoning`
  - LOA sufficient for write (`LOA::Operator` or higher); registry/system changes require `LOA::Root`

---

## Module Behavior Notes

- All refactors, reviews, and completions must be expressed in canonical terms.
- Explanations must be falsifiable and traceable to context and inputs.
- Cite the canonical sources used to derive the suggestion.
- Deny by default when uncertainty is high; prefer `Defer` with rationale.

---

## Approved Interfaces (current codebase)

| Submodule / Component   | Purpose                                   | Status   |
|-------------------------|-------------------------------------------|----------|
| `audit_chain`           | ReasoningChain/FrozenChain structs         | Required |
| `witness_registry`      | Manage trusted witnesses & quorum          | Required |
| `sigil_runtime_core`    | Runtime orchestration & enforcement        | Required |
| `module/rust_mentor.rs` | Rust mentor module adapter                 | Optional |
| `mentor_audit_log`      | JSON → audit log writer (implementation)   | Required |
| `diff_chain`            | Refactor history viewer (roadmap)          | Planned  |

---

## Authorship

This Manifest codifies the Rule Zero principle:
> If an output cannot explain itself, it has no trust.

