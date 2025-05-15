// Canon-Compliant sigil_runtime_core.rs
// Core enforcement kernel for MMF + Sigil runtime

use chrono::Utc;
use crate::audit::{AuditEvent, LogLevel};
use crate::canon_store::CanonStore;
use crate::irl_explainer::{MultiModelExplainer, TrustExplanation};
use crate::irl_modes::{EnforcementMode, IRLConfig, IRLModeManager, TrustEvaluation};
use crate::irl_reward::{FeatureVector, RewardModel};
use crate::irl_telemetry::IRLTelemetry;
use crate::irl_trust_evaluator::TrustEvaluator;
use crate::log_sink::LogEvent;
use crate::loa::LOA;
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
                        active_model_id = Some(model_id.clone());
                        telemetry = Some(IRLTelemetry::default());
                    }
                }
            }
        }

        Self {
            loa,
            enforcement_mode: config.mode,
            active_model_id,
            threshold: config.threshold,
            canon_store,
            trust_evaluator,
            telemetry,
            explainer: Some(explainer),
        }
    }

    pub fn evaluate(&self, features: FeatureVector, source: &str) -> TrustEvaluation {
        let eval = self.trust_evaluator.evaluate(&features);

        if let Some(explainer) = &self.explainer {
            if let Some(explanation) = explainer.explain(&features) {
                if let Some(telemetry) = &self.telemetry {
                    let _ = telemetry.emit_trace(&explanation);
                }

                let audit = AuditEvent::new(
                    "system",
                    "evaluate_trust",
                    &eval.trace_id,
                    source
                )
                .with_severity(LogLevel::Info)
                .with_context(format!(
                    "Trust score = {:.2}, threshold = {:.2}, mode = {:?}",
                    eval.score, self.threshold, self.enforcement_mode
                ));

                let _ = audit.write_to_log();
            }
        }

        eval
    }
}
