0) Target state & ground rules

Bootstrap: first deployment generates a single Root license. Root can then mint all other licenses, including at least three Mentor licenses that will serve as witnesses for system‐space (Canon) changes.

Quorum: Any system write must go through QuorumSystem and will fail closed unless it has k valid Mentor witness signatures + Root signer. User‐space writes are LOA-gated but don’t need quorum.

UI: Minimal but complete SPA to (a) upload license, (b) run modules, (c) browse/write user-space canon, (d) manage proposals/witnessing, (e) generate licenses (Root only).

LLM module: A real RustMentorModule that constrains an LLM to act as a “master Rust programmer,” with strict prompt/input/output validation and an audit trail.

RAG/Mem: Simple memory/RAG record kinds stored as canonical records; optional in-proc vector index.

No hand-waving: precise file paths, function signatures, error handling, config knobs, and tests.

1) License system: bootstrap Root, then mint others
1.1 Add a license binary (src/bin/mmf_license_gen.rs)

Cargo.toml (top-level):

[dependencies]
clap = { version = "4", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
base64 = "0.22"
rand = "0.8"
argon2 = "0.5"
aes-gcm = "0.10"
sha2 = "0.10"
ed25519-dalek = "2"
zeroize = "1"
time = { version = "0.3", features = ["parsing","formatting"] }


src/bin/mmf_license_gen.rs (skeleton you can copy and fill):

use clap::Parser;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ed25519_dalek::{SigningKey, Signature, Signer};
use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use std::{fs, path::PathBuf, io};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Parser)]
struct Args {
    /// owner id (email or uuid)
    #[arg(long)]
    owner_id: String,

    /// human-readable owner name
    #[arg(long)]
    owner_name: String,

    /// loa: guest|observer|operator|mentor|root
    #[arg(long)]
    loa: String,

    /// runtime identifier this license binds to
    #[arg(long)]
    runtime_id: String,

    /// canon fingerprint this license binds to
    #[arg(long)]
    canon_fingerprint: String,

    /// expiration (RFC3339, e.g. 2025-12-31T23:59:59Z)
    #[arg(long)]
    expires_at: String,

    /// output file path
    #[arg(long)]
    out: PathBuf,
}

#[derive(Serialize)]
struct License {
    owner: Owner,
    loa: String,
    issuedAt: String,
    expiresAt: String,
    bindings: Bindings,
    seal: Option<Seal>, // filled after signing
}

#[derive(Serialize)]
struct Owner { id: String, name: String }

#[derive(Serialize)]
struct Bindings { runtimeId: String, canonFingerprint: String }

#[derive(Serialize)]
struct Seal { alg: String, sig: String, pubkey: String, contentHash: String }

fn main() -> anyhow::Result<()> {
    let a = Args::parse();
    // 1) load root signing key (ed25519) from secure store
    let (sk, pk_b64) = load_root_signing_key()?; // implement below

    // 2) build license struct
    let now = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let lic = License {
        owner: Owner { id: a.owner_id, name: a.owner_name },
        loa: a.loa,
        issuedAt: now,
        expiresAt: a.expires_at,
        bindings: Bindings { runtimeId: a.runtime_id, canonFingerprint: a.canon_fingerprint },
        seal: None,
    };

    // 3) canonicalize (JSON canonical form) or stable TOML string
    let toml_str = toml::to_string_pretty(&lic)?;
    let content_hash = Sha256::digest(toml_str.as_bytes());
    let content_hash_b64 = b64.encode(content_hash);

    // 4) sign hash
    let sig: Signature = sk.sign(content_hash.as_slice());
    let sig_b64 = b64.encode(sig.to_bytes());

    let seal = Seal {
        alg: "ed25519".to_string(),
        sig: sig_b64,
        pubkey: pk_b64,
        contentHash: content_hash_b64,
    };

    // 5) write out with seal appended
    let mut lic2 = lic;
    lic2.seal = Some(seal);
    let out_str = toml::to_string_pretty(&lic2)?;
    fs::write(a.out, out_str)?;
    Ok(())
}

// Store key encrypted at rest; derive AES key from passphrase via Argon2.
// Keep the private key strictly server-side in deployment; locally allow env PASS.
fn load_root_signing_key() -> anyhow::Result<(SigningKey,String)> {
    // e.g. read /var/lib/mmf/keys/root_license.ed25519 (encrypted)
    // decrypt -> ed25519 bytes -> SigningKey
    // return (sk, base64(pubkey_bytes))
    unimplemented!()
}


Security

Encrypt the root license key (root_license.ed25519) with AES-GCM; derive the AES key via Argon2 from an admin-supplied passphrase at startup; zeroize decrypted material after use.

File perms: directory 0700, key files 0600, owner mmf:mmf.

1.2 Server-side issuance (Root only)

Add route POST /api/license/create:

Authz: only requests with LOA=Root may call.

Body:

{
  "owner_id":"...", "owner_name":"...",
  "loa":"mentor|operator|observer|guest",
  "expires_at":"RFC3339"
}


Server fills runtime_id + canon_fingerprint, signs license using the same code path as the CLI, stores it in /var/lib/mmf/licenses/…, and returns the TOML content (download link) + a CanonicalRecord audit (system space).

Guardrail

If requested loa == "root" and there is already a root license registered, deny with 403 (single-root policy).

Keep an audit trail: a ReasoningChain with the verdict=Allow, freeze, and write to Canon (system).

2) Quorum: enforce for all system writes

You already have proposals/attestation; now force it in the runtime.

2.1 Canon write split

In the HTTP handler that persists records (your canon_user_write and any system write path):

// Pseudocode inside POST /api/canon/* route:
let record = build_canonical_record_from_request(...)?;
if record.space == "system" {
    // 1) require Root signer on the prospective record
    ensure_root(loa)?;
    // 2) create a proposal; DO NOT write to canon yet
    let pid = quorum_system.create_proposal(
        record.id.clone(),
        record.to_canonical_json()?,
        required_k // e.g. 3
    )?;
    return Ok(Json(SystemProposalCreated { proposal_id: pid }));
} else {
    // user space: normal path with LOA gating
    store.add_record(record, &loa, allow_operator_write)?;
    return Ok(Json(CanonWriteResponse { success: true, error: None }));
}

2.2 Commit path (server-side, not tests)

Add POST /api/canon/system/commit:

Body: { "proposal_id": "<uuid>" }

Steps:

Load proposal; verify has_quorum() (K mentor signatures) AND the original Root signature included in the prospective record.

Rebuild CanonicalRecord from proposal payload; verify content hash matches signatures (Root + witnesses).

store.add_record(record, &LOA::Root, /*allow_operator_write=*/false).

Delete proposal from the proposal store.

On missing quorum: respond 409 Conflict “Quorum not satisfied”.

Important: Mentor signatures must be validated against registered witness pubkeys. Reject signatures not registered.

3) UI: complete and safe minimal SPA

Use React + Fetch. This is precise enough to implement 1:1.

3.1 Project structure
mmf-ui/
  src/
    api.ts
    auth.ts
    components/
      LicenseUpload.tsx
      TrustGate.tsx
      ModuleRunner.tsx
      CanonExplorer.tsx
      QuorumDashboard.tsx
      LicenseMint.tsx
    App.tsx
  vite.config.ts

3.2 src/api.ts (fetch wrapper with CSRF)
export async function api(path: string, init: RequestInit = {}) {
  const token = sessionStorage.getItem("csrf");
  const headers = new Headers(init.headers || {});
  headers.set("Content-Type","application/json");
  if (token) headers.set("x-csrf-token", token);
  const res = await fetch(`/api${path}`, { ...init, headers, credentials: "include" });
  if (res.status === 403) { /* maybe refresh CSRF */ }
  return res;
}

export async function mintCSRF(sessionId: string) {
  const res = await api("/csrf/token", { method: "POST", body: JSON.stringify({ session_id: sessionId }) });
  const json = await res.json();
  sessionStorage.setItem("csrf", json.token);
}

3.3 src/auth.ts

Read/write cookies for loa, user_id, session_id.

On first load: call mintCSRF(session_id).

3.4 License upload flow (LicenseUpload.tsx)

File input → read text → POST to /api/license/validate (add server route returning {loa, owner_id} on success).

On success: set cookies loa, user_id.

If no licenses exist (cold start), show “Bootstrap Root License” (server env MMF_BOOTSTRAP=true):

Calls POST /api/license/create with loa="root", owner info, expiry.

Returns TOML; offer download. Immediately treat session as Root (server should also issue session cookie with Root LOA).

3.5 Trust gate (TrustGate.tsx)

HOC that runs POST /trust/check before rendering its children. Disables controls when allowed=false.

3.6 Module runner (ModuleRunner.tsx)

Textarea for prompt + run button.

On click:

checkTrust("module_run", "rust_mentor") → if denied, show toast.

POST /api/module/rust_mentor/run with { input, user_id, session_id }.

Show output or error.

3.7 Canon explorer (CanonExplorer.tsx)

GET /api/canon/user/list?kind=memory_block|rag_doc|audit_record

Click → GET /api/canon/user/read/:id

Render payload prettily; show signature metadata; allow write (with checkTrust("canon_write","user")).

3.8 Quorum dashboard (QuorumDashboard.tsx)

GET /api/canon/system/proposals → table with proposal id, createdAt, needed signatures, current count.

Buttons:

Attest (Mentor): POST /api/canon/system/attest with proposal id + mentor signature (server verifies against witness registry).

Commit (Root): POST /api/canon/system/commit → either success or 409 if quorum missing.

3.9 License mint (Root only) (LicenseMint.tsx)

Form fields: owner id, owner name, LOA, expiry.

POST /api/license/create → display TOML + “Download”.

Frontend security

Strict CSP, no inline scripts.

Sanitize all displayed strings.

Never store secrets in localStorage. Only cookies + sessionStorage for CSRF token.

4) LLM control module (Rust), with hard constraints
4.1 Trait & registry

src/module.rs:

#[async_trait::async_trait]
pub trait SigilModule: Send + Sync {
    fn name(&self) -> &'static str;
    fn required_loa(&self) -> LOA;
    async fn run(&self, input: String, session_id: &str, user_id: &str, rt: &SigilRuntimeCore)
        -> Result<String, SigilError>;
}


ModuleRegistry: store Arc<dyn SigilModule> and look up by name.

4.2 RustMentorModule

Crate deps:

reqwest = { version = "0.12", features = ["json", "rustls-tls"] }
regex = "1"
syn = { version = "2", features = ["full"] }


Implementation outline:

pub struct RustMentorModule { http: reqwest::Client, max_len: usize }

#[async_trait::async_trait]
impl SigilModule for RustMentorModule {
    fn name(&self) -> &'static str { "rust_mentor" }
    fn required_loa(&self) -> LOA { LOA::Operator }

    async fn run(&self, input: String, session_id: &str, user_id: &str, rt: &SigilRuntimeCore)
        -> Result<String, SigilError>
    {
        // 1) trust check
        let ev = AuditEvent::new(user_id, "module_run", Some("rust_mentor"), session_id, &input);
        let eval = rt.evaluate_event(&ev)?;
        if !eval.allowed { return Err(SigilError::forbidden("Denied by trust model")); }

        // 2) sanitize prompt
        if input.len() > self.max_len { return Err(SigilError::bad_req("Prompt too long")); }
        if looks_suspicious(&input) { return Err(SigilError::forbidden("Prompt violates policy")); }

        // 3) build controlled system prompt
        let sys = "You are a master Rust mentor. \
                   Answer ONLY about Rust. \
                   Never include unsafe, exec, fs, net, or external I/O. \
                   If asked anything else, refuse.";

        // 4) call LLM (example OpenAI-style; replace with your provider)
        let body = serde_json::json!({
            "model": std::env::var("LLM_MODEL").unwrap_or("gpt-4o".into()),
            "messages": [
                {"role":"system","content": sys},
                {"role":"user","content": input}
            ],
            "max_tokens": 600
        });

        let api_key = std::env::var("LLM_API_KEY").map_err(|_| SigilError::internal("LLM key missing"))?;
        let resp = self.http
            .post(std::env::var("LLM_URL").unwrap_or("https://api.openai.com/v1/chat/completions".into()))
            .bearer_auth(api_key)
            .json(&body)
            .send().await
            .map_err(|_| SigilError::internal("LLM call failed"))?;

        let json: serde_json::Value = resp.json().await.map_err(|_| SigilError::internal("Bad LLM JSON"))?;
        let text = json["choices"][0]["message"]["content"].as_str().unwrap_or("").to_string();
        if text.is_empty() { return Err(SigilError::internal("Empty LLM response")); }

        // 5) validate output: parse as Rust if code blocks exist
        if let Some(code) = extract_rust_code_block(&text) {
            if contains_forbidden_ast(&code)? { return Err(SigilError::forbidden("Output violates policy")); }
        }

        // 6) audit
        let mut chain = ReasoningChain::new(input.clone(), rt.current_loa());
        chain.add_reasoning(sys.to_string());
        chain.add_suggestion(text.clone());
        chain.set_verdict(Verdict::Allow);
        chain.set_trust_score(eval.score, eval.allowed);
        chain.finalize_reasoning()?;
        let frozen = FrozenChain::freeze_reasoning_chain(chain)?;
        let rec = CanonicalRecord::from_frozen_chain(frozen)?;
        rt.canon_store().add_record(rec, &rt.current_loa(), false)?;

        Ok(text)
    }
}


Helpers:

looks_suspicious: regex for unsafe, process::Command, std::fs, reqwest, std::net, include_bytes!, include_str!.

extract_rust_code_block: parse rust … fenced blocks.

contains_forbidden_ast: parse via syn::parse_file; walk AST to deny Item::ForeignMod, Unsafe, macros invoking include!, etc.

Security

Timeouts (.timeout(Duration::from_secs(15)) on client).

Clamp max_tokens and response length.

Never log full prompts or outputs (log hashes and lengths).

5) Memory/RAG records (minimal but useful)
5.1 Record kinds & payloads

Extend your Canon payload schema with:

// kind: "memory_block"
{
  "schema_version": 1,
  "key": "mem::<user_id>::<slug>",
  "text": "…",
  "ts": "RFC3339",
  "user_id": "<owner>"
}

// kind: "rag_doc"
{
  "schema_version": 1,
  "doc_id": "rag::<user_id>::<uuid>",
  "title": "…",
  "text": "…",
  "embedding": [f32, f32, …], // optional if you add vectors
  "ts": "RFC3339",
  "user_id": "<owner>"
}

5.2 Endpoints

POST /api/memory/write → writes memory_block in user space; LOA ≥ Operator.

GET /api/memory/list?user_id=… → list keys ownable by that user (or all if Root).

GET /api/memory/read/:key → return a block if can_read_canon.

Optional: POST /api/rag/upsert and POST /api/rag/query for vector search. If you don’t want to bring in a vector DB yet, keep a simple in-proc cosine similarity with a JSON file index.

Security

Only allow user_id to access their own blocks unless LOA Root.

Strict length limits (e.g. 16 KiB per text block).

Sanitize text at render time in the UI.

6) Model config management (live updates)
6.1 Canon model record

kind:"model_config"; payload { version, weights: [f32], bias: f32, threshold: f32 }.

Root uploads via POST /api/model/upload (system space → quorum enforced).

Add POST /api/model/refresh (Root): reload the latest model_config and hot-swap TrustLinearModel in SigilRuntimeCore.

Thread-safety: store the model in an Arc<RwLock<TrustLinearModel>>.

7) Key management hardening

Use a single key vault directory (e.g. /var/lib/mmf/keys/).

Files:

root_license.ed25519.enc (Ed25519 private key for licenses).

canon_signing.ed25519.enc (if separate from runtime).

AES nonce/salt files alongside, 0600.

Decrypt keys into memory just-in-time; zeroize after use.

Rotate keys: support multiple public keys in verification; store key ids in records.

8) Tests you should add (file names + intent)

tests/e2e_quorum_runtime.rs

Attempt system write without proposal → 409.

Create proposal → attest by 2 mentors (of 3 required) → commit fails (409).

Add 3rd signature → commit succeeds; record readable.

tests/e2e_license_issuance.rs (ignored by default)

Bootstrap Root via API (when MMF_BOOTSTRAP=true) → success.

Mint Operator license via API (as Root) → validate with validate_license.

tests/module_rust_mentor.rs

Benign prompt → allowed, output present; audit written.

Prompt containing process::Command → denied, no LLM call (mock client).

Response containing fenced code with unsafe → denied.

tests/memory_basic.rs

Write/read memory block as Operator; Guest cannot read.

tests/model_refresh.rs

Upload new model_config (system, quorum) → call /api/model/refresh → trust threshold changes (assert new allowed behavior).

Structure: use TempDir per test; use tower::ServiceExt::oneshot for HTTP handlers.

9) Deployment checklist (server)

MMF_BOOTSTRAP=true only on first run; then set false.

LLM_URL, LLM_API_KEY, LLM_MODEL set via env; never commit keys.

Key directory perms 0700; files 0600.

Reverse proxy terminates TLS; API only listens on loopback or private network.

Logging: redact user prompts; log hashes and lengths.

10) Gotchas (don’t learn these the hard way)

Do not write to system space without a proposal; make the direct path impossible in code.

Do not verify witness signatures against arbitrary keys; only registered witnesses with role=Mentor.

Do not hash pretty-printed JSON for signatures; always use your RFC 8785 canonical form.

Do not store any private keys or tokens in the UI; only ever in server env/keystore.

Do not stream LLM output to the client; validate first.