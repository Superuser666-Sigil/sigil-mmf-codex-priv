Minimal next moves (to reach a believable MVP)

Crypto: Implement real Ed25519 verify in witness_registry::validate_witness_signature and store witness keys with integrity; require valid signatures when attesting proposals and before committing system-space writes.

Single Canon backend: pick sled (or the encrypted sled) and retire file-based canon files/canon.json helpers in runtime code paths. All read/write/list flows should go through CanonStore.

Sign on write: In /api/canon/* handlers, canonicalize → hash → sign with the active key from KeyStore → persist CanonicalRecord { hash, sig, pub_key, … }.

Fix runtime glue: Correct run_sigil_session arg naming and config usage; ensure model/threshold refresh either comes from a clearly named Canon record or from config only (don’t half-do both).

Tests:

JCS conformance vectors (strings, numbers, Unicode, deeply nested).

E2E test: spin Axum app, hit /api/trust/check with varying LOA and rate-limit windows, assert decisions.

Canon write/verify round-trip: write record, reload, verify signature.

Quorum: create proposal → collect k signatures (real verify) → commit → confirm Canon mutation.

CSRF issuance + logging hygiene: Add a token-mint endpoint and ensure log dirs exist; fail closed if logging can’t open files.

Error typing: standardize on SigilError/SigilResult across stores, web, and runtime.