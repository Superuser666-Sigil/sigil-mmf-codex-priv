
# Codex Nexus Module Manifest (Immutable Trust Foundation)

## Module Name: Codex Mentor (v2)
### Status: Core Required
### Enforced: Yes (Sigil Trusted Module Class)

---

## Reasoning Chain Compliance (REQUIRED)

Each Codex-related module must output a structured JSON object with the following fields:

```json
{
  "input": "Raw code or query from user.",
  "context": "Canonical context from Codex Nexus.",
  "reasoning": "Summary of match, interpretation, or logic path.",
  "suggestion": "LLM or IRL-generated output or action.",
  "verdict": "Allow, Deny, Defer, or Manual Review",
  "audit": "Timestamped log hash, session ID, and LOA signature.",
  "IRL": {
    "model_id": "sigil_trust_v1",
    "score": 0.0–1.0 float (Trust weight of output)",
    "allowed": true|false
  }
}
```

### Violations of this structure result in:
- Sigil API access revocation
- Module LOA lock (minimum LOA = Root required)
- Canon strip: No write privileges to Codex Canon
- Mirage cannot use results in training

---

## Scope

- Language Support: Rust, Python, TypeScript, Bash
- Trust Enforcement: Enabled
- Canon Mutation: Only allowed if `verdict == "Allow"` and `IRL.allowed == true` under `LOA::Root`

---

## Module Behavior Notes

- All refactors, reviews, or completions must be explained in canonical terms.
- No hallucinations. No unverifiable logic.
- All suggestions must cite their context.

---

## Approved Interfaces

| Submodule         | Description                        | Status   |
|-------------------|------------------------------------|----------|
| mirage_mentor     | CLI tool to compare code to Codex  | Required |
| mentor_explainer  | Human-readable output formatter     | Optional |
| mentor_audit_log  | JSON-to-log IRL audit writer        | Required |
| codex_diff_chain  | Future refactor history viewer      | Planned  |

---

## Authorship

This Codex Manifest defines the **Rule Zero Framework**:
> If an output cannot explain itself, it has no trust.

