use crate::loa::LoaLevel;
use crate::module_scope::ModuleScope;
use crate::sigil_integrity::WitnessSignature;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;
use ed25519_dalek::{Signer, Verifier};
use base64::Engine;

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum Verdict {
    Allow,
    Deny,
    Defer,
    ManualReview,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IRLInfo {
    pub model_id: String,
    pub score: f32,
    pub allowed: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditMetadata {
    pub timestamp: DateTime<Utc>,
    pub session_id: String,
    pub loa: LoaLevel,
    pub chain_id: String,
}

// Phase 1: ReasoningChain - Mutable process for "thinking out loud"
#[derive(Debug, Serialize, Deserialize, Clone)]
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
    // SECURITY: Ed25519 signature fields for content integrity
    pub content_hash: String,
    pub signature: Option<String>, // Base64 encoded Ed25519 signature
    pub public_key: Option<String>, // Base64 encoded Ed25519 public key
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
            content_hash: String::new(),
            signature: None,
            public_key: None,
        }
    }

    pub fn add_context(&mut self, ctx: impl Into<String>) {
        self.context = ctx.into();
    }

    pub fn add_reasoning(&mut self, logic: impl Into<String>) {
        self.reasoning = logic.into();
    }

    pub fn add_reasoning_step(&mut self, step: impl Into<String>) {
        if !self.reasoning.is_empty() {
            self.reasoning.push('\n');
        }
        self.reasoning.push_str(&step.into());
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

    pub fn add_witness(&mut self, witness_id: &str, signature: &str) {
        self.witnesses.push(WitnessSignature {
            witness_id: witness_id.to_string(),
            signature: signature.to_string(),
        });
    }

    pub fn finalize_reasoning(&mut self) -> Result<(), String> {
        // Validate reasoning completeness
        if self.reasoning.is_empty() {
            return Err("Reasoning chain cannot be empty".into());
        }

        if self.verdict == Verdict::Allow && !self.irl.allowed {
            return Err(
                "Inconsistent verdict and IRL trust: verdict=Allow but IRL.allowed=false".into(),
            );
        }

        if self.verdict == Verdict::Allow && self.witnesses.len() < 3 {
            return Err("Witness quorum not satisfied for Canon mutation.".into());
        }

        Ok(())
    }

    // SECURITY: Sign the reasoning chain with Ed25519
    pub fn sign(&mut self, signing_key: &ed25519_dalek::SigningKey) -> Result<(), String> {
        // Create content hash (excluding signature fields)
        let content_json = serde_json::json!({
            "input": self.input,
            "context": self.context,
            "reasoning": self.reasoning,
            "suggestion": self.suggestion,
            "verdict": self.verdict,
            "audit": self.audit,
            "irl": self.irl,
            "scope": self.scope,
            "witnesses": self.witnesses,
        });
        
        let content_str = serde_json::to_string(&content_json)
            .map_err(|e| format!("Failed to serialize content: {e}"))?;
        
        // Calculate SHA256 hash
        let mut hasher = sha2::Sha256::new();
        hasher.update(content_str.as_bytes());
        let hash_result = hasher.finalize();
        self.content_hash = format!("{:x}", hash_result);
        
        // Sign the hash
        let signature = signing_key.sign(hash_result.as_slice());
        self.signature = Some(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, signature.to_bytes()));
        self.public_key = Some(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, signing_key.verifying_key().to_bytes()));
        
        Ok(())
    }
    
    // SECURITY: Verify the signature
    pub fn verify_integrity(&self) -> Result<bool, String> {
        // Reconstruct content hash
        let content_json = serde_json::json!({
            "input": self.input,
            "context": self.context,
            "reasoning": self.reasoning,
            "suggestion": self.suggestion,
            "verdict": self.verdict,
            "audit": self.audit,
            "irl": self.irl,
            "scope": self.scope,
            "witnesses": self.witnesses,
        });
        
        let content_str = serde_json::to_string(&content_json)
            .map_err(|e| format!("Failed to serialize content: {e}"))?;
        
        // Calculate expected hash
        let mut hasher = sha2::Sha256::new();
        hasher.update(content_str.as_bytes());
        let expected_hash = format!("{:x}", hasher.finalize());
        
        // Verify hash matches
        if self.content_hash != expected_hash {
            return Ok(false);
        }
        
        // Verify signature if present
        if let (Some(sig_b64), Some(pubkey_b64)) = (&self.signature, &self.public_key) {
            let signature_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sig_b64)
                .map_err(|e| format!("Invalid signature encoding: {e}"))?;
            let pubkey_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, pubkey_b64)
                .map_err(|e| format!("Invalid public key encoding: {e}"))?;
            
            if signature_bytes.len() != 64 || pubkey_bytes.len() != 32 {
                return Ok(false);
            }
            
            // Convert Vec<u8> to arrays
            let mut sig_array = [0u8; 64];
            sig_array.copy_from_slice(&signature_bytes);
            let mut pubkey_array = [0u8; 32];
            pubkey_array.copy_from_slice(&pubkey_bytes);
            
            let signature = ed25519_dalek::Signature::from_bytes(&sig_array);
            let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_array)
                .map_err(|e| format!("Invalid public key format: {e}"))?;
            
            // Verify signature
            let hash_bytes = hex::decode(&self.content_hash)
                .map_err(|e| format!("Invalid hash format: {e}"))?;
            
            verifying_key.verify(&hash_bytes, &signature)
                .map(|_| true)
                .map_err(|e| format!("Signature verification failed: {e}"))
        } else {
            // No signature present, consider unsigned chains invalid
            Ok(false)
        }
    }

    // Legacy method for backward compatibility
    pub fn finalize(self) -> Result<(), String> {
        let mut chain = self;
        chain.finalize_reasoning()?;

        let serialized = serde_json::to_string_pretty(&chain)
            .map_err(|e| format!("Serialization failed: {e}"))?;

        println!("[REASONING CHAIN]\n{serialized}");
        Ok(())
    }
}

// Phase 2: FrozenChain - Immutable record for cryptographic integrity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrozenChain {
    // Immutable identity
    pub chain_id: String,
    pub frozen_at: DateTime<Utc>,
    pub version: String,

    // Cryptographic integrity
    pub content_hash: String,
    /// Optional Ed25519 signature over the content hash.
    /// This replaces the previous toy signature implementation.
    pub signature: Option<String>,
    /// Base64 encoded Ed25519 public key corresponding to the signature.
    pub public_key: Option<String>,
    pub merkle_root: String,

    // Training record data
    pub input_snapshot: InputSnapshot,
    pub reasoning_trace: ReasoningTrace,
    pub output_snapshot: OutputSnapshot,
    pub metadata: TrainingMetadata,

    // Lineage tracking
    pub parent_chain_ids: Vec<String>,
    pub dataset_version: String,
    pub model_version: String,

    // Verification data
    pub witnesses: Vec<CryptographicWitness>,
    pub verification_proofs: Vec<VerificationProof>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputSnapshot {
    pub raw_input: String,
    pub preprocessed_input: String,
    pub input_features: HashMap<String, f32>,
    pub input_metadata: HashMap<String, String>,
    pub input_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningTrace {
    pub reasoning_steps: Vec<ReasoningStep>,
    pub intermediate_decisions: Vec<Decision>,
    pub confidence_scores: Vec<f32>,
    pub uncertainty_measures: Vec<f32>,
    pub reasoning_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningStep {
    pub step_id: String,
    pub description: String,
    pub logic: String,
    pub confidence: f32,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub decision_id: String,
    pub description: String,
    pub rationale: String,
    pub confidence: f32,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputSnapshot {
    pub final_output: String,
    pub output_confidence: f32,
    pub output_uncertainty: f32,
    pub alternative_outputs: Vec<String>,
    pub output_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingMetadata {
    pub model_id: String,
    pub training_run_id: String,
    pub hyperparameters: HashMap<String, String>,
    pub training_data_version: String,
    pub evaluation_metrics: HashMap<String, f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptographicWitness {
    pub witness_id: String,
    pub signature: String,
    pub timestamp: DateTime<Utc>,
    pub authority: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationProof {
    pub proof_id: String,
    pub proof_type: String,
    pub proof_data: String,
    pub verified_at: DateTime<Utc>,
}

impl FrozenChain {
    pub fn freeze_reasoning_chain(chain: ReasoningChain) -> Result<Self, String> {
        // Ensure reasoning is complete
        if chain.verdict == Verdict::Defer {
            return Err("Cannot freeze incomplete reasoning chain".into());
        }

        // Create immutable snapshots
        let input_snapshot = InputSnapshot::from_chain(&chain)?;
        let reasoning_trace = ReasoningTrace::from_chain(&chain)?;
        let output_snapshot = OutputSnapshot::from_chain(&chain)?;
        let metadata = TrainingMetadata::from_chain(&chain)?;

        // Generate cryptographic integrity (content hash)
        let content_hash = Self::generate_content_hash(
            &input_snapshot,
            &reasoning_trace,
            &output_snapshot,
            &metadata,
        )?;

        // SECURITY: Sign the content hash using a freshly generated Ed25519 key.
        // In a production system this key should be provided by a trusted authority.
        use ed25519_dalek::{SigningKey, Signer};
        use base64::Engine;
        let mut rng = rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        let hash_bytes = hex::decode(&content_hash)
            .map_err(|e| format!("Invalid content hash: {e}"))?;
        let sig = signing_key.sign(&hash_bytes);
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
        let pub_key_b64 =
            base64::engine::general_purpose::STANDARD.encode(verifying_key.to_bytes());

        // Generate Merkle root
        let merkle_root =
            Self::generate_merkle_root(&input_snapshot, &reasoning_trace, &output_snapshot)?;

        // Create immutable frozen record
        Ok(FrozenChain {
            chain_id: chain.audit.chain_id.clone(),
            frozen_at: Utc::now(),
            version: "1.0".to_string(),
            content_hash: content_hash.clone(),
            signature: Some(signature_b64),
            public_key: Some(pub_key_b64),
            merkle_root,
            input_snapshot,
            reasoning_trace,
            output_snapshot,
            metadata: metadata.clone(),
            parent_chain_ids: Vec::new(),
            dataset_version: "1.0".to_string(),
            model_version: metadata.model_id.clone(),
            witnesses: chain
                .witnesses
                .iter()
                .map(|w| CryptographicWitness {
                    witness_id: w.witness_id.clone(),
                    signature: w.signature.clone(),
                    timestamp: Utc::now(),
                    authority: w.witness_id.clone(),
                })
                .collect(),
            verification_proofs: Vec::new(),
        })
    }

    fn generate_content_hash(
        input: &InputSnapshot,
        reasoning: &ReasoningTrace,
        output: &OutputSnapshot,
        metadata: &TrainingMetadata,
    ) -> Result<String, String> {
        let mut hasher = Sha256::new();

        // Hash each component
        hasher.update(&input.input_hash);
        hasher.update(&reasoning.reasoning_hash);
        hasher.update(&output.output_hash);
        hasher.update(
            &serde_json::to_string(metadata)
                .map_err(|e| format!("Metadata serialization failed: {e}"))?,
        );

        Ok(format!("{:x}", hasher.finalize()))
    }

    fn generate_merkle_root(
        input: &InputSnapshot,
        reasoning: &ReasoningTrace,
        output: &OutputSnapshot,
    ) -> Result<String, String> {
        let mut hasher = Sha256::new();
        hasher.update(&input.input_hash);
        hasher.update(&reasoning.reasoning_hash);
        hasher.update(&output.output_hash);
        Ok(format!("{:x}", hasher.finalize()))
    }

    pub fn verify_integrity(&self) -> Result<bool, String> {
        // Verify content hash
        let expected_hash = Self::generate_content_hash(
            &self.input_snapshot,
            &self.reasoning_trace,
            &self.output_snapshot,
            &self.metadata,
        )?;
        let hash_valid = expected_hash == self.content_hash;

        // Verify Merkle root
        let expected_merkle = Self::generate_merkle_root(
            &self.input_snapshot,
            &self.reasoning_trace,
            &self.output_snapshot,
        )?;
        let merkle_valid = expected_merkle == self.merkle_root;

        // Verify signature if present
        let sig_valid = if let (Some(sig_b64), Some(pub_b64)) = (&self.signature, &self.public_key)
        {
            let sig_bytes = base64::engine::general_purpose::STANDARD
                .decode(sig_b64)
                .map_err(|e| format!("Invalid signature encoding: {e}"))?;
            let pub_bytes = base64::engine::general_purpose::STANDARD
                .decode(pub_b64)
                .map_err(|e| format!("Invalid public key encoding: {e}"))?;
            if sig_bytes.len() != 64 || pub_bytes.len() != 32 {
                false
            } else {
                let signature = ed25519_dalek::Signature::try_from(sig_bytes.as_slice())
                    .map_err(|e| format!("Invalid signature: {e}"))?;
                let verifying_key =
                    ed25519_dalek::VerifyingKey::from_bytes(&pub_bytes.try_into().unwrap())
                        .map_err(|e| format!("Invalid public key: {e}"))?;
                let hash_bytes = hex::decode(&self.content_hash)
                    .map_err(|e| format!("Invalid content hash: {e}"))?;
                verifying_key.verify(&hash_bytes, &signature).is_ok()
            }
        } else {
            false
        };

        Ok(hash_valid && merkle_valid && sig_valid)
    }

    pub fn link_to_parent(&mut self, parent_chain: &FrozenChain) -> Result<(), String> {
        // Verify parent chain integrity
        if !parent_chain.verify_integrity()? {
            return Err("Parent chain integrity verification failed".into());
        }

        self.parent_chain_ids.push(parent_chain.chain_id.clone());
        Ok(())
    }

    pub fn get_lineage(&self) -> Vec<String> {
        let mut lineage = self.parent_chain_ids.clone();
        lineage.push(self.chain_id.clone());
        lineage
    }
}

// Conversion implementations
impl InputSnapshot {
    fn from_chain(chain: &ReasoningChain) -> Result<Self, String> {
        let mut hasher = Sha256::new();
        hasher.update(chain.input.as_bytes());
        let input_hash = format!("{:x}", hasher.finalize());

        Ok(InputSnapshot {
            raw_input: chain.input.clone(),
            preprocessed_input: chain.input.clone(), // Will be enhanced with preprocessing
            input_features: HashMap::new(),          // Will be enhanced with feature extraction
            input_metadata: HashMap::new(),
            input_hash,
        })
    }
}

impl ReasoningTrace {
    fn from_chain(chain: &ReasoningChain) -> Result<Self, String> {
        let mut hasher = Sha256::new();
        hasher.update(chain.reasoning.as_bytes());
        let reasoning_hash = format!("{:x}", hasher.finalize());

        // Parse reasoning into steps (simple implementation)
        let reasoning_steps = vec![ReasoningStep {
            step_id: "step_1".to_string(),
            description: "Main reasoning".to_string(),
            logic: chain.reasoning.clone(),
            confidence: chain.irl.score,
            timestamp: chain.audit.timestamp,
        }];

        Ok(ReasoningTrace {
            reasoning_steps,
            intermediate_decisions: Vec::new(),
            confidence_scores: vec![chain.irl.score],
            uncertainty_measures: vec![1.0 - chain.irl.score],
            reasoning_hash,
        })
    }
}

impl OutputSnapshot {
    fn from_chain(chain: &ReasoningChain) -> Result<Self, String> {
        let mut hasher = Sha256::new();
        hasher.update(chain.suggestion.as_bytes());
        let output_hash = format!("{:x}", hasher.finalize());

        Ok(OutputSnapshot {
            final_output: chain.suggestion.clone(),
            output_confidence: chain.irl.score,
            output_uncertainty: 1.0 - chain.irl.score,
            alternative_outputs: Vec::new(),
            output_hash,
        })
    }
}

impl TrainingMetadata {
    fn from_chain(chain: &ReasoningChain) -> Result<Self, String> {
        Ok(TrainingMetadata {
            model_id: chain.irl.model_id.clone(),
            training_run_id: chain.audit.session_id.clone(),
            hyperparameters: HashMap::new(),
            training_data_version: "canon_v1".to_string(),
            evaluation_metrics: HashMap::new(),
        })
    }
}
