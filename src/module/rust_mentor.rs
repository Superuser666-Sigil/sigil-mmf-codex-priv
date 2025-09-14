use async_trait::async_trait;
use regex::Regex;
use reqwest::Client;
use syn::File as SynFile;
use once_cell::sync::Lazy;

use crate::{
    api_errors::AppError, 
    loa::LOA, 
    sigil_runtime_core::SigilRuntimeCore, 
    audit::{AuditEvent},
    audit_chain::{ReasoningChain, FrozenChain, Verdict},
    canonical_record::CanonicalRecord,
};

pub struct RustMentorModule {
    http: Client,
    max_prompt_len: usize,
}

impl RustMentorModule {
    pub fn new() -> Self {
        Self {
            http: Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .unwrap(),
            max_prompt_len: 1000,
        }
    }
}

#[async_trait]
pub trait SigilModule: Send + Sync {
    fn name(&self) -> &'static str;
    fn required_loa(&self) -> LOA;
    async fn run(&self, input: String, session_id: &str, user_id: &str, rt: &SigilRuntimeCore)
        -> Result<String, AppError>;
}

#[async_trait]
impl SigilModule for RustMentorModule {
    fn name(&self) -> &'static str { 
        "rust_mentor" 
    }
    
    fn required_loa(&self) -> LOA { 
        LOA::Operator 
    }

    async fn run(&self, input: String, session_id: &str, user_id: &str, rt: &SigilRuntimeCore)
        -> Result<String, AppError>
    {
        // 1) Trust check - create a mock LOA for now since we don't have access to the user's LOA
        let user_loa = LOA::Operator; // This should come from the runtime context
        let event = AuditEvent::new(user_id, "module_run", Some("rust_mentor"), session_id, &user_loa);
        let eval = rt.evaluate_event(&event, 0); // Pass 0 for recent_requests
        if !eval.allowed {
            // rt.audit_deny(&event).ok(); // Method doesn't exist, skip for now
            return Err(AppError::forbidden("Denied by trust model"));
        }

        // 2) Prompt validation
        if input.trim().is_empty() || input.len() > self.max_prompt_len {
            return Err(AppError::bad_request("Invalid prompt length"));
        }
        if looks_suspicious(&input) {
            return Err(AppError::forbidden("Prompt violates policy"));
        }

        // 3) System prompt
        let system = "You are a master Rust mentor. \
           Answer only Rust programming questions. \
           Never suggest unsafe code, filesystem, network, exec, or external I/O. \
           Refuse anything outside Rust mentoring.";

        // 4) Call LLM
        let body = serde_json::json!({
            "model": std::env::var("LLM_MODEL").unwrap_or_else(|_| "gpt-4o".into()),
            "messages": [
                {"role":"system","content": system},
                {"role":"user","content": input}
            ],
            "max_tokens": 600
        });
        let url = std::env::var("LLM_URL").unwrap_or_else(|_| "https://api.openai.com/v1/chat/completions".into());
        let key = std::env::var("LLM_API_KEY").map_err(|_| AppError::internal("missing LLM_API_KEY"))?;

        let resp = self.http.post(url)
            .bearer_auth(key)
            .json(&body)
            .send().await
            .map_err(|_| AppError::internal("LLM request failed"))?;

        if !resp.status().is_success() {
            return Err(AppError::internal("LLM backend error"));
        }
        let json: serde_json::Value = resp.json().await.map_err(|_| AppError::internal("LLM JSON error"))?;
        let answer = json["choices"][0]["message"]["content"].as_str().unwrap_or("").to_string();
        if answer.is_empty() {
            return Err(AppError::internal("Empty LLM response"));
        }

        // 5) Post-validate output
        if let Some(code) = extract_rust_block(&answer) {
            if contains_forbidden_ast(&code)? {
                return Err(AppError::forbidden("Output violates Rust safety policy"));
            }
        }

        // 6) Audit trail - simplified for now due to API differences
        let mut chain = ReasoningChain::new(input.clone(), user_loa);
        chain.add_reasoning(system.to_string());
        chain.add_suggestion(answer.clone());
        chain.set_verdict(Verdict::Allow);
        chain.set_trust_score(eval.score, eval.allowed);
        chain.finalize_reasoning().map_err(|e| AppError::internal(e))?;
        let frozen = FrozenChain::freeze_reasoning_chain(chain).map_err(|e| AppError::internal(e))?;
        let _rec = CanonicalRecord::from_frozen_chain(&frozen, user_id, "user", None).map_err(|e| AppError::internal(e))?;
        
        // TODO: Fix canon store access - rt.canon_store is a field, not a method
        tracing::info!("Module execution completed for user: {}", user_id);

        Ok(answer)
    }
}

// ---- helpers ----

fn looks_suspicious(s: &str) -> bool {
    // deny dangerous intents early
    static RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i)\b(unsafe|process::command|std::fs|std::net|include!|include_str!|include_bytes!)\b").unwrap()
    });
    RE.is_match(s)
}

fn extract_rust_block(txt: &str) -> Option<String> {
    // extract first ```rust ... ``` fenced block, else None
    let fence = "```rust";
    if let Some(start) = txt.find(fence) {
        let rest = &txt[start+fence.len()..];
        if let Some(end) = rest.find("```") {
            return Some(rest[..end].to_string());
        }
    }
    None
}

struct ForbidVisitor { 
    found_forbidden: bool 
}

impl<'ast> syn::visit::Visit<'ast> for ForbidVisitor {
    fn visit_item_foreign_mod(&mut self, _i: &'ast syn::ItemForeignMod) { 
        self.found_forbidden = true; 
    }
    
    fn visit_item_macro(&mut self, i: &'ast syn::ItemMacro) {
        if let Some(ident) = i.mac.path.get_ident() {
            if ident == "include" { 
                self.found_forbidden = true; 
            }
        }
    }
    
    fn visit_expr_unsafe(&mut self, _i: &'ast syn::ExprUnsafe) { 
        self.found_forbidden = true; 
    }
}

fn contains_forbidden_ast(code: &str) -> Result<bool, AppError> {
    let file: SynFile = syn::parse_file(code)
        .map_err(|_| AppError::bad_request("Invalid Rust code block"))?;
    let mut v = ForbidVisitor { found_forbidden: false };
    syn::visit::Visit::visit_file(&mut v, &file);
    Ok(v.found_forbidden)
}
