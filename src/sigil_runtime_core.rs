
//! sigil_runtime_core.rs
//! Core enforcement and validation logic for MMF + Sigil runtime.
//! Integrates trust model, IRL reward system, fallback logic, telemetry, and enforcement modes.

use crate::audit::AuditEvent;
use crate::canon_store::CanonStore;
use crate::canon_store_sled::CanonStoreSled;
use crate::errors::{SigilResult, SafeLock};
use crate::irl_explainer::{MultiModelExplainer, TrustExplanation};
use crate::irl_modes::{EnforcementMode, IRLConfig, TrustEvaluation};
use crate::irl_reward::RewardModel;
use crate::irl_telemetry::IRLTelemetry;
use crate::irl_trust_evaluator::TrustEvaluator;
use crate::log_sink::LogEvent;
use crate::loa::LOA;

use std::sync::Arc;
use std::sync::Mutex;
use log::{info, warn, error, debug};

pub struct SigilRuntimeCore {
    pub loa: LOA,
    pub enforcement_mode: EnforcementMode,
    pub active_model_id: Option<String>,
    pub threshold: f64,
    pub canon_store: Arc<Mutex<dyn CanonStore>>,
    pub trust_evaluator: TrustEvaluator,
    pub telemetry: Option<IRLTelemetry>,
    pub explainer: Option<MultiModelExplainer>,
}

impl SigilRuntimeCore {
    pub fn new(loa: LOA, canon_store: Arc<Mutex<dyn CanonStore>>, config: IRLConfig) -> SigilResult<Self> {
        let mut trust_evaluator = TrustEvaluator::new();
        let mut explainer = MultiModelExplainer::new();
        let mut active_model_id = None;
        let mut telemetry = None;

        if let Some(model_id) = &config.active_model {
            // Use safe lock instead of unwrap
            match canon_store.safe_lock() {
                Ok(store) => {
                    let entries = store.list_entries(Some("irl_reward"), &loa);
                    debug!("Found {} IRL reward entries in canon store", entries.len());
                    
                    for entry in entries {
                        match serde_json::from_str::<RewardModel>(&entry.content) {
                            Ok(model) if model.model_id == *model_id => {
                                trust_evaluator.add_model(model.clone(), config.threshold);
                                explainer.add_model(model.clone(), config.threshold);
                                active_model_id = Some(model.model_id.clone());
                                
                                if config.telemetry_enabled {
                                    telemetry = Some(IRLTelemetry::new("model_loaded", &model.model_id));
                                }
                                
                                info!("Loaded IRL model: {} with threshold: {}", model.model_id, config.threshold);
                                break;
                            },
                            Ok(_) => {
                                debug!("Skipping IRL model with different ID");
                            },
                            Err(e) => {
                                warn!("Failed to deserialize IRL model from entry {}: {}", entry.id, e);
                            }
                        }
                    }
                    
                    if active_model_id.is_none() {
                        warn!("Requested IRL model '{model_id}' not found in canon store");
                    }
                },
                Err(e) => {
                    error!("Failed to acquire canon store lock during initialization: {e}");
                    return Err(e);
                }
            }
        }

        info!("SigilRuntimeCore initialized with LOA: {:?}, enforcement: {:?}", loa, config.enforcement_mode);
        
        Ok(Self {
            loa,
            enforcement_mode: config.enforcement_mode,
            active_model_id,
            threshold: config.threshold,
            canon_store,
            trust_evaluator,
            telemetry,
            explainer: if config.explanation_enabled { Some(explainer) } else { None },
        })
    }

    /// Evaluate trust for an audit event
    pub fn evaluate_event(&self, event: &AuditEvent) -> TrustEvaluation {
        let model_id = match &self.active_model_id {
            Some(id) => id.clone(),
            None => {
                return TrustEvaluation::new(0.0, true)
            }
        };

        let (score, allowed) = match self.trust_evaluator.evaluate_event(event, &model_id) {
            Ok((s, a)) => (s, a),
            Err(_) => (0.0, true), // fallback
        };

        // Log trust score
        if self.enforcement_mode.is_logging() {
            let log = LogEvent::new(
                "trust_eval",
                &format!("Action '{}' by {} scored {:.4} ({})", event.action, event.who, score, model_id),
            );
            log.write_to("logs/trust_scores.log").ok();
        }

        // Log telemetry
        if let Some(ref telemetry) = self.telemetry {
            telemetry.record_decision(event, score, allowed);
        }

        TrustEvaluation::new(score, allowed)
    }

    /// Validate an action against trust model
    pub fn validate_action(&self, event: &AuditEvent) -> Result<bool, &'static str> {
        let evaluation = self.evaluate_event(event);
        
        match self.enforcement_mode {
            EnforcementMode::Passive => Ok(true), // Always allow in passive mode
            EnforcementMode::Active => Ok(evaluation.allowed),
            EnforcementMode::Strict => {
                if evaluation.allowed {
                    Ok(true)
                } else {
                    Err("Action denied by strict trust enforcement")
                }
            }
        }
    }

    /// Generate explanation for trust decision
    pub fn explain(&self, event: &AuditEvent) -> Option<TrustExplanation> {
        self.explainer.as_ref().map(|explainer| explainer.explain_event(event))
    }

    /// Refresh models from canon store
    pub fn refresh_models(&mut self) -> SigilResult<()> {
        // Get all model entries from canon using safe lock
        let store = self.canon_store.safe_lock()
            .map_err(|e| {
                error!("Failed to acquire canon store lock for model refresh: {e}");
                e
            })?;
        let model_entries = store.list_entries(Some("model"), &self.loa);
        
        info!("Refreshing models from canon store, found {} entries", model_entries.len());

        // Update active model if available
        if let Some(active_model_id) = &self.active_model_id {
            let active_model = model_entries.iter()
                .find(|entry| entry.id == *active_model_id);

            if active_model.is_none() {
                return Err(crate::errors::SigilError::canon("refresh_models", "Active model not found in canon store"));
            }
        }

        // Update threshold from canon if available
        if let Some(threshold_entry) = model_entries.iter()
            .find(|entry| entry.id == "trust_threshold") {
            // Parse content as JSON if it's a string
            if let Ok(content_json) = serde_json::from_str::<serde_json::Value>(&threshold_entry.content) {
                if let Some(threshold_value) = content_json.as_object().and_then(|obj| obj.get("value")) {
                    if let Some(threshold) = threshold_value.as_f64() {
                        self.threshold = threshold;
                    }
                }
            }
        }

        println!("✅ Refreshed {} models from canon store", model_entries.len());
        Ok(())
    }

    /// Enable telemetry
    pub fn enable_telemetry(&mut self) {
        self.telemetry = Some(IRLTelemetry::new("runtime_telemetry", "enabled"));
    }

    /// Enable explanation
    pub fn enable_explanation(&mut self) {
        self.explainer = Some(MultiModelExplainer::new());
    }

    /// Get runtime status
    pub fn status(&self) -> serde_json::Value {
        serde_json::json!({
            "loa": format!("{:?}", self.loa),
            "enforcement_mode": format!("{:?}", self.enforcement_mode),
            "active_model": self.active_model_id,
            "threshold": self.threshold,
            "telemetry_enabled": self.telemetry.is_some(),
            "explanation_enabled": self.explainer.is_some(),
        })
    }
}

// Missing function that is referenced in other modules
pub fn run_sigil_session(config: &crate::config_loader::MMFConfig) -> Result<(), String> {
    // Create a default IRL config
    let irl_config = IRLConfig::default();
    
    // Use the Sled-based canon store for persistence
    let store = CanonStoreSled::new("data/canon_store").map_err(|e| format!("Failed to create canon store: {e}"))?;
    let canon_store = Arc::new(Mutex::new(store));
    
    // Initialize runtime core
    let mut runtime = SigilRuntimeCore::new(LOA::Observer, canon_store, irl_config)
        .map_err(|e| format!("Failed to initialize runtime: {e}"))?;
    
    // Set up telemetry if enabled
    if config.irl.telemetry_enabled {
        runtime.enable_telemetry();
    }
    
    // Set up explanation if enabled
    if config.irl.explanation_enabled {
        runtime.enable_explanation();
    }
    
    // Refresh models from canon store
    runtime.refresh_models()
        .map_err(|e| format!("Failed to refresh models: {e}"))?;
    
    // Start the runtime session
    println!("🚀 Sigil runtime session started");
    println!("   LOA: {:?}", runtime.loa);
    println!("   Enforcement: {:?}", runtime.enforcement_mode);
    println!("   Active Model: {}", runtime.active_model_id.as_deref().unwrap_or("none"));
    println!("   Threshold: {:.2}", runtime.threshold);
    
    // Keep the runtime alive (in a real implementation, this would handle events)
    std::thread::sleep(std::time::Duration::from_secs(1));
    
    println!("✅ Sigil runtime session completed");
    Ok(())
}
