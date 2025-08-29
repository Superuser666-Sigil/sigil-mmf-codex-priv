//! sigil_runtime_core.rs
//! Core enforcement and validation logic for MMF + Sigil runtime.
//! Integrates trust model, IRL reward system, fallback logic, telemetry, and enforcement modes.

use crate::audit::AuditEvent;
use crate::canon_store::CanonStore;
use crate::canon_store_sled::CanonStoreSled;
use crate::errors::{SafeLock, SigilResult};
use crate::irl_explainer::{MultiModelExplainer, TrustExplanation};
use crate::irl_modes::{EnforcementMode, IRLConfig, TrustEvaluation};
use crate::irl_reward::RewardModel;
use crate::irl_telemetry::IRLTelemetry;
use crate::irl_trust_evaluator::TrustEvaluator;
use crate::loa::LOA;
use crate::log_sink::LogEvent;

// Import the logistic trust model registry and features.  This will allow
// SigilRuntimeCore to evaluate audit events using a real trust model
// instead of the keyword‑based or IRL stubs.  The TrustModelRegistry
// provides a default linear model with five features and a logistic
// threshold.
use crate::trust_linear::{TrustModelRegistry, TrustFeatures};

use log::{debug, error, info, warn};
use std::sync::Arc;
use std::sync::Mutex;

pub struct SigilRuntimeCore {
    pub loa: LOA,
    pub enforcement_mode: EnforcementMode,
    pub active_model_id: Option<String>,
    pub threshold: f64,
    pub canon_store: Arc<Mutex<dyn CanonStore>>,
    pub trust_evaluator: TrustEvaluator,

    /// Registry of logistic trust models.  In the absence of a custom IRL
    /// model, the runtime will use this registry to compute trust scores
    /// based on action, target, LOA, rate limiting and input entropy.
    pub trust_registry: TrustModelRegistry,
    pub telemetry: Option<IRLTelemetry>,
    pub explainer: Option<MultiModelExplainer>,
}

impl SigilRuntimeCore {
    pub fn new(
        loa: LOA,
        canon_store: Arc<Mutex<dyn CanonStore>>,
        config: IRLConfig,
    ) -> SigilResult<Self> {
        let mut trust_evaluator = TrustEvaluator::new();
        let mut explainer = MultiModelExplainer::new();
        let mut active_model_id = None;
        let mut telemetry = None;

        if let Some(model_id) = &config.active_model {
            match canon_store.safe_lock() {
                Ok(store) => {
                    // Fetch reward model records from canon
                    let records = store.list_records(Some("irl_reward"), &loa);
                    debug!("Found {} IRL reward entries in canon store", records.len());
                    for rec in records {
                        // Payload should be a TrustedKnowledgeEntry serialized as JSON
                        if let Ok(entry) = serde_json::from_value::<crate::trusted_knowledge::TrustedKnowledgeEntry>(rec.payload.clone()) {
                            // entry.content should contain the RewardModel JSON
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
                                }
                                Ok(_) => {
                                    debug!("Skipping IRL model with different ID");
                                }
                                Err(e) => {
                                    warn!("Failed to deserialize IRL model from record {}: {}", rec.id, e);
                                }
                            }
                        }
                    }
                    if active_model_id.is_none() {
                        warn!("Requested IRL model '{model_id}' not found in canon store");
                    }
                }
                Err(e) => {
                    error!("Failed to acquire canon store lock during initialization: {e}");
                    return Err(e);
                }
            }
        }

        info!(
            "SigilRuntimeCore initialized with LOA: {:?}, enforcement: {:?}",
            loa, config.enforcement_mode
        );

        // Initialize a default trust model registry.  This registry
        // contains a default linear model with equal weights and bias.
        let trust_registry = TrustModelRegistry::default();

        Ok(Self {
            loa,
            enforcement_mode: config.enforcement_mode,
            active_model_id,
            threshold: config.threshold,
            canon_store,
            trust_evaluator,
            telemetry,
            explainer: if config.explanation_enabled {
                Some(explainer)
            } else {
                None
            },

            trust_registry,
        })
    }

    /// Evaluate trust for an audit event.  This method computes
    /// features for the logistic model using the supplied
    /// `recent_requests` count (rate limiter window) and the event
    /// context.  It returns a TrustEvaluation containing the
    /// decision score and allow flag.
    pub fn evaluate_event(&self, event: &AuditEvent, recent_requests: usize) -> TrustEvaluation {
        // Build the input string for entropy calculation.  In the
        // absence of full context, use action and target combined.
        let input_for_entropy = match &event.target {
            Some(t) => format!("{} {}", event.action, t),
            None => event.action.clone(),
        };
        // Construct logistic features from the audit event.  The
        // TrustFeatures struct derives risk values from the action,
        // target and LOA, and includes the recent request count and
        // input entropy.  This yields a 5‑dimensional feature vector.
        let features = TrustFeatures::new(
            &event.action,
            event.target.as_deref(),
            &self.loa,
            recent_requests,
            &input_for_entropy,
        );
        let (score_f64, allowed) =
            self.trust_registry.evaluate_with_model(None, &features);
        let score = score_f64 as f32;

        // Log trust score using the logistic model
        if self.enforcement_mode.is_logging() {
            let log = LogEvent::new(
                "trust_eval",
                &format!(
                    "Action '{}' by {} scored {:.4} (logistic)",
                    event.action, event.who, score
                ),
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
    pub fn validate_action(
        &self,
        event: &AuditEvent,
        recent_requests: usize,
    ) -> Result<bool, &'static str> {
        let evaluation = self.evaluate_event(event, recent_requests);
        match self.enforcement_mode {
            EnforcementMode::Passive => Ok(true),
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
        self.explainer
            .as_ref()
            .map(|explainer| explainer.explain_event(event))
    }

    /// Refresh models from canon store
    pub fn refresh_models(&mut self) -> SigilResult<()> {
        // Get all model entries from canon using safe lock
        let store = self.canon_store.safe_lock().map_err(|e| {
            error!("Failed to acquire canon store lock for model refresh: {e}");
            e
        })?;
        let model_entries = store.list_records(Some("model"), &self.loa);

        info!(
            "Refreshing models from canon store, found {} entries",
            model_entries.len()
        );

        // Update active model if available.  Canonical records store the
        // trusted knowledge entry as a JSON payload; we must extract
        // the TrustedKnowledgeEntry from the payload field to inspect
        // model IDs.
        if let Some(active_model_id) = &self.active_model_id {
            let mut found = false;
            for rec in &model_entries {
                if let Ok(entry_val) = serde_json::from_value::<crate::trusted_knowledge::TrustedKnowledgeEntry>(rec.payload.clone()) {
                    if entry_val.id == *active_model_id {
                        found = true;
                        break;
                    }
                }
            }
            if !found {
                return Err(crate::errors::SigilError::canon(
                    "refresh_models",
                    "Active model not found in canon store",
                ));
            }
        }

        // Update threshold from canon if available.  Look for a record
        // with id "trust_threshold" in the model records; parse its
        // payload as JSON {"value": number}.
        for rec in &model_entries {
            if rec.id == "trust_threshold" {
                if let Ok(val) = serde_json::from_value::<serde_json::Value>(rec.payload.clone()) {
                    if let Some(threshold_value) = val.as_object().and_then(|obj| obj.get("value")) {
                        if let Some(th) = threshold_value.as_f64() {
                            self.threshold = th;
                        }
                    }
                }
                break;
            }
        }

        println!(
            "✅ Refreshed {} models from canon store",
            model_entries.len()
        );
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
    let store = CanonStoreSled::new("data/canon_store")
        .map_err(|e| format!("Failed to create canon store: {e}"))?;
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
    runtime
        .refresh_models()
        .map_err(|e| format!("Failed to refresh models: {e}"))?;

    // Start the runtime session
    println!("🚀 Sigil runtime session started");
    println!("   LOA: {:?}", runtime.loa);
    println!("   Enforcement: {:?}", runtime.enforcement_mode);
    println!(
        "   Active Model: {}",
        runtime.active_model_id.as_deref().unwrap_or("none")
    );
    println!("   Threshold: {:.2}", runtime.threshold);

    // Keep the runtime alive (in a real implementation, this would handle events)
    std::thread::sleep(std::time::Duration::from_secs(1));

    println!("✅ Sigil runtime session completed");
    Ok(())
}
