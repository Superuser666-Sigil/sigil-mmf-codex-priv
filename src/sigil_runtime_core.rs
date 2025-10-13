//! sigil_runtime_core.rs
//! Core enforcement and validation logic for MMF + Sigil runtime.
//! Integrates trust model, fallback logic, telemetry, and enforcement modes.

use crate::audit::AuditEvent;
use crate::canon_store::CanonStore;

use crate::errors::{SafeLock, SigilError, SigilResult};
use crate::loa::LOA;
use crate::log_sink::LogEvent;
use crate::runtime_config::{EnforcementMode, RuntimeConfig, TrustEvaluation};
use std::str::FromStr;

// Import the logistic trust model registry and features.  This will allow
// SigilRuntimeCore to evaluate audit events using a real trust model.
// The TrustModelRegistry provides a default linear model with five features
// and a logistic threshold.
use crate::trust_linear::{TrustFeatures, TrustModelRegistry};

// Import the quorum system for witness signature validation
use crate::quorum_system::QuorumSystem;

// Import the witness registry for managing trusted public keys
use crate::witness_registry::WitnessRegistry;

// Import the module system for executing LOA-gated modules
use crate::module_loader::{HelloModule, ModuleRegistry};

use std::sync::{Arc, Mutex};
use tracing::{error, info};

pub struct SigilRuntimeCore {
    pub loa: LOA,
    pub enforcement_mode: EnforcementMode,

    pub threshold: f64,
    pub canon_store: Arc<Mutex<dyn CanonStore>>,

    /// Registry of logistic trust models used to compute trust scores
    /// based on action, target, LOA, rate limiting and input entropy.
    pub trust_registry: TrustModelRegistry,

    /// Quorum system for managing witness signatures on system-space writes
    pub quorum_system: std::sync::Mutex<QuorumSystem>,

    /// Registry of trusted witnesses for signature validation
    pub witness_registry: Arc<WitnessRegistry>,

    /// Module registry for executing LOA-gated modules
    pub module_registry: std::sync::Mutex<ModuleRegistry>,
}

impl SigilRuntimeCore {
    pub fn new(
        loa: LOA,
        canon_store: Arc<Mutex<dyn CanonStore>>,
        config: RuntimeConfig,
    ) -> SigilResult<Self> {
        // IRL-related initialization removed - using logistic trust model only

        info!(
            "SigilRuntimeCore initialized with LOA: {:?}, enforcement: {:?}",
            loa, config.enforcement_mode
        );

        // Initialize a default trust model registry.  This registry
        // contains a default linear model with equal weights and bias.
        let trust_registry = TrustModelRegistry::default();

        // Initialize the witness registry
        let witness_registry = Arc::new(WitnessRegistry::new(canon_store.clone())?);

        // Initialize the quorum system for witness signature validation
        let quorum_system = std::sync::Mutex::new(QuorumSystem::new(witness_registry.clone()));

        // Initialize the module registry and register built-in modules
        let mut module_registry = ModuleRegistry::new();
        module_registry.register_module("hello", Box::new(HelloModule));
        let module_registry = std::sync::Mutex::new(module_registry);

        info!("Initialized module registry with built-in modules");

        Ok(Self {
            loa,
            enforcement_mode: config.enforcement_mode,
            threshold: config.threshold,
            canon_store,
            trust_registry,
            quorum_system,
            witness_registry,
            module_registry,
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
        let (score_f64, allowed) = self.trust_registry.evaluate_with_model(None, &features);
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

        // Telemetry removed with IRL cleanup
        TrustEvaluation::new(score, allowed)
    }

    /// Validate an action against trust model
    pub fn validate_action(&self, event: &AuditEvent, recent_requests: usize) -> SigilResult<bool> {
        let evaluation = self.evaluate_event(event, recent_requests);
        match self.enforcement_mode {
            EnforcementMode::Passive => Ok(true),
            EnforcementMode::Active => Ok(evaluation.allowed),
            EnforcementMode::Strict => {
                if evaluation.allowed {
                    Ok(true)
                } else {
                    Err(SigilError::Irl {
                        message: format!(
                            "Action '{}' denied under strict enforcement",
                            event.action
                        ),
                    })
                }
            }
        }
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

        // Active model tracking removed with IRL cleanup

        // Update threshold from canon if available.  Look for a record
        // with id "trust_threshold" in the model records; parse its
        // payload as JSON {"value": number}.
        for rec in &model_entries {
            if rec.id == "trust_threshold" {
                if let Ok(val) = serde_json::from_value::<serde_json::Value>(rec.payload.clone())
                    && let Some(threshold_value) = val.as_object().and_then(|obj| obj.get("value"))
                    && let Some(th) = threshold_value.as_f64()
                {
                    self.threshold = th;
                }
                break;
            }
        }

        info!("Refreshed {} models from canon store", model_entries.len());
        Ok(())
    }

    /// Get runtime status
    pub fn status(&self) -> serde_json::Value {
        serde_json::json!({
            "loa": format!("{:?}", self.loa),
            "enforcement_mode": format!("{:?}", self.enforcement_mode),
            "threshold": self.threshold,
        })
    }
}

/// Run a Sigil session with proper config integration
pub fn run_sigil_session(config: &crate::config_loader::MMFConfig) -> SigilResult<()> {
    let enforcement_mode = match config.irl.enforcement_mode.to_lowercase().as_str() {
        "active" => EnforcementMode::Active,
        "strict" => EnforcementMode::Strict,
        _ => EnforcementMode::Active,
    };

    let runtime_config = RuntimeConfig {
        threshold: config.irl.threshold,
        enforcement_mode,
        telemetry_enabled: false,
        active_model: None,
        explanation_enabled: false,
        model_refresh_from_canon: config.irl.model_refresh_from_canon,
    };

    let canon_store_path = "data/canon_store";
    let encryption_key =
        crate::keys::KeyManager::get_encryption_key().map_err(|e| SigilError::Encryption {
            operation: format!("load CANON_ENCRYPTION_KEY: {e}"),
        })?;

    let store =
        crate::canon_store_sled_encrypted::CanonStoreSled::new(canon_store_path, &encryption_key)
            .map_err(|e| SigilError::Canon {
            operation: "open encrypted canon store".to_string(),
            message: e,
        })?;
    let canon_store = Arc::new(Mutex::new(store));

    let session_loa = LOA::from_str(&config.trust.default_loa)
        .map_err(|e| SigilError::validation("default_loa", e.to_string()))?;

    let mut runtime = SigilRuntimeCore::new(session_loa, canon_store, runtime_config.clone())?;

    if runtime_config.model_refresh_from_canon {
        runtime.refresh_models()?;
        info!("Using canon-based threshold: {:.2}", runtime.threshold);
    } else {
        info!("Using config-based threshold: {:.2}", runtime.threshold);
    }

    info!(
        loa = ?runtime.loa,
        enforcement = ?runtime.enforcement_mode,
        threshold = runtime.threshold,
        canon_store = canon_store_path,
        "Sigil runtime session ready"
    );

    Ok(())
}
