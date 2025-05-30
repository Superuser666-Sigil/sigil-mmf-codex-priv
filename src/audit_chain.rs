use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::loa::LoaLevel;
use crate::module_scope::ModuleScope;
use crate::sigil_integrity::WitnessSignature;

#[derive(Debug, Serialize, Deserialize)]
pub enum Verdict {
    Allow,
    Deny,
    Defer,
    ManualReview,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IRLInfo {
    pub model_id: String,
    pub score: f32,
    pub allowed: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditMetadata {
    pub timestamp: DateTime<Utc>,
    pub session_id: String,
    pub loa: LoaLevel,
    pub chain_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReasoningChain {
    pub input: String,
    pub context: String,
    pub reasoning: String,
    pub suggestion: String,
    pub verdict: Verdict,
    pub audit: AuditMetadata,
    pub irl: IRLInfo,
    pub scope: ModuleScope,
    pub witnesses: Vec<WitnessSignature>,
}

impl ReasoningChain {
    pub fn new(input: impl Into<String>, loa: LoaLevel) -> Self {
        ReasoningChain {
            input: input.into(),
            context: String::new(),
            reasoning: String::new(),
            suggestion: String::new(),
            verdict: Verdict::Defer,
            audit: AuditMetadata {
                timestamp: Utc::now(),
                session_id: Uuid::new_v4().to_string(),
                loa,
                chain_id: Uuid::new_v4().to_string(),
            },
            irl: IRLInfo {
                model_id: "sigil_trust_v1".into(),
                score: 0.0,
                allowed: false,
            },
            scope: ModuleScope {
                user_id: "unset".into(),
                module_id: "unset".into(),
                session_id: "unset".into(),
            },
            witnesses: Vec::new(),
        }
    }

    pub fn add_context(&mut self, ctx: impl Into<String>) {
        self.context = ctx.into();
    }

    pub fn add_reasoning(&mut self, logic: impl Into<String>) {
        self.reasoning = logic.into();
    }

    pub fn add_suggestion(&mut self, suggestion: impl Into<String>) {
        self.suggestion = suggestion.into();
    }

    pub fn set_verdict(&mut self, verdict: Verdict) {
        self.verdict = verdict;
    }

    pub fn set_irl_score(&mut self, score: f32, allowed: bool) {
        self.irl.score = score;
        self.irl.allowed = allowed;
    }

    pub fn set_scope(&mut self, scope: ModuleScope) {
        self.scope = scope;
    }

    pub fn set_witnesses(&mut self, w: Vec<WitnessSignature>) {
        self.witnesses = w;
    }

    pub fn finalize(self) -> Result<(), String> {
        if self.verdict == Verdict::Allow && !self.irl.allowed {
            return Err("Inconsistent verdict and IRL trust: verdict=Allow but IRL.allowed=false".into());
        }

        if self.verdict == Verdict::Allow && self.witnesses.len() < 3 {
            return Err("Witness quorum not satisfied for Canon mutation.".into());
        }

        let serialized = serde_json::to_string_pretty(&self)
            .map_err(|e| format!("Serialization failed: {}", e))?;

        println!("[REASONING CHAIN]\n{}", serialized);
        Ok(())
    }
}