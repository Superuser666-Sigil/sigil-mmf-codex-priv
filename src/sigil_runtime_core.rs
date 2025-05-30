
//! sigil_runtime_core.rs
//! Core enforcement and validation logic for MMF + Sigil runtime.
//! Integrates trust model, IRL reward system, fallback logic, telemetry, and enforcement modes.

use crate::audit::AuditEvent;
use crate::canon_store::CanonStore;
use crate::irl_explainer::{MultiModelExplainer, TrustExplanation};
use crate::irl_modes::{EnforcementMode, IRLConfig, IRLModeManager, TrustEvaluation};
use crate::irl_reward::{FeatureVector, RewardModel};
use crate::irl_telemetry::IRLTelemetry;
use crate::irl_trust_evaluator::TrustEvaluator;
use crate::log_sink::LogEvent;
use crate::loa::LOA;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

pub struct SigilRuntimeCore {
    pub loa: LOA,
    pub enforcement_mode: EnforcementMode,
    pub active_model_id: Option<String>,
    pub threshold: f64,
    pub canon_store: Box<dyn CanonStore>,
    pub trust_evaluator: TrustEvaluator,
    pub telemetry: Option<IRLTelemetry>,
    pub explainer: Option<MultiModelExplainer>,
}

impl SigilRuntimeCore {
    pub fn new(loa: LOA, canon_store: Box<dyn CanonStore>, config: IRLConfig) -> Self {
        let mut trust_evaluator = TrustEvaluator::new();
        let mut explainer = MultiModelExplainer::new();
        let mut active_model_id = None;
        let mut telemetry = None;

        if let Some(model_id) = &config.active_model {
            let entries = canon_store.list_entries(Some("irl_reward"), &loa);
            for entry in entries {
                if let Ok(model) = serde_json::from_str::<RewardModel>(&entry.content) {
                    if model.id == *model_id {
                        trust_evaluator.add_model(model.clone(), config.threshold);
                        explainer.add_model(model.clone(), config.threshold);
                        active_model_id = Some(model.id.clone());
                        if config.telemetry_enabled {
                            telemetry = Some(IRLTelemetry::new(&model.id));
                        }
                    }
                }
            }
        }

        Self {
            loa,
            enforcement_mode: config.enforcement_mode,
            active_model_id,
            threshold: config.threshold,
            canon_store,
            trust_evaluator,
            telemetry,
            explainer: if config.explanation_enabled { Some(explainer) } else { None },
        }
    }

    /// Evaluate trust for an audit event
    pub fn evaluate_event(&self, event: &AuditEvent) -> TrustEvaluation {
        let model_id = match &self.active_model_id {
            Some(id) => id.clone(),
            None => {
                return TrustEvaluation::new(
                    &format!("{}:{}", event.session_id, event.timestamp),
                    "none",
                    0.0,
                    self.threshold,
                    self.enforcement_mode,
                )
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
                Some(&event.session_id),
                Some("score"),
            );
            log.write_to("logs/trust_scores.log").ok();
        }

        // Log telemetry
        if let Some(ref telemetry) = self.telemetry {
            telemetry.record_decision(event, score, allowed);
        }

        TrustEvaluation::new(
            &format!("{}:{}", event.session_id, event.timestamp),
            &model_id,
            score,
            self.threshold,
            self.enforcement_mode,
        )
    }

    /// Decide whether to allow or block an event based on current mode
    pub fn validate_action(&self, event: &AuditEvent) -> Result<bool, &'static str> {
        let eval = self.evaluate_event(event);

        // Enforce or not based on enforcement mode
        let decision = eval.effective_decision();

        if !decision {
        if eval.score < self.threshold * 0.5 {
            if let Some(explanation) = self.explain(event) {
                let details = serde_json::to_string(&explanation).unwrap_or_default();
                let context_log = LogEvent::new(
                    "sigil_core",
                    &format!("BLOCK DETAILS: {}", details),
                    Some(&event.session_id),
                    Some("explain"),
                );
                context_log.write_to("logs/irl_explanations.log").ok();
            }
        }
    
            let log = LogEvent::new(
                "sigil_core",
                &format!("BLOCKED: {} accessing {}", event.who, event.action),
                Some(&event.session_id),
                Some("block"),
            );
            log.write_to("logs/irl_enforcement.log").ok();
        }

        Ok(decision)
    }

    /// Provide explanation for a decision if available
    pub fn explain(&self, event: &AuditEvent) -> Option<TrustExplanation> {
        let model_id = self.active_model_id.as_ref()?;
        let (_, features) = self.trust_evaluator.evaluate_event(event, model_id).ok()?;
        self.explainer
            .as_ref()?
            .explain_decision(model_id, event, &features)
            .ok()
    }

    pub fn refresh_models(&mut self) -> Result<(), &'static str> {
        if let Some(model_id) = &self.active_model_id {
            let entries = self.canon_store.list_entries(Some("irl_reward"), &self.loa);
            for entry in entries {
                if let Ok(model) = serde_json::from_str::<RewardModel>(&entry.content) {
                    if &model.id == model_id {
                        self.trust_evaluator.add_model(model.clone(), self.threshold);
                        if let Some(explainer) = &mut self.explainer {
                            explainer.add_model(model.clone(), self.threshold);
                        }
                        return Ok(());
                    }
                }
            }
            return Err("Active model not found in canon store");
        }
        Err("No active model configured")
    }

    pub fn status(&self) -> serde_json::Value {
        json!({
            "mode": self.enforcement_mode.to_string(),
            "active_model": self.active_model_id,
            "threshold": self.threshold,
            "has_telemetry": self.telemetry.is_some(),
            "has_explainer": self.explainer.is_some(),
            "loa": format!("{:?}", self.loa),
        })
    }

}
