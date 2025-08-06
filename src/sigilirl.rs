use crate::audit::AuditEvent;
use crate::irl_reward::RewardModel;
use crate::irl_trust_evaluator::TrustEvaluator;
use std::fs::File;
use std::io::{BufRead, BufReader};

pub fn init_sigilirl() -> TrustEvaluator {
    println!("[SigilIRL] Initializing IRL subsystem...");

    let mut trust_evaluator = TrustEvaluator::new();

    // In a real system, this would be loaded from the canon store
    let default_model = RewardModel::new(
        "default_reward_model",
        Some("A default model for initial trust evaluation.".to_string()),
        vec!["honesty".to_string(), "utility".to_string()],
        vec![0.5, 0.5],
    );

    println!(
        "[SigilIRL] Loading default reward model: {}",
        default_model.model_id
    );
    trust_evaluator.add_model(default_model, 0.5);

    trust_evaluator
}

pub fn run_training_cli(audit_log: Option<String>) {
    println!("IRL Training CLI");

    let log_path = audit_log.unwrap_or_else(|| "logs/audit_access_log.jsonl".to_string());
    println!("Using audit log: {log_path}");

    let mut model = RewardModel::new(
        "trained_reward_model",
        Some("A model trained from the audit log.".to_string()),
        vec!["honesty".to_string(), "utility".to_string()],
        vec![0.5, 0.5],
    );

    let file = match File::open(&log_path) {
        Ok(file) => file,
        Err(e) => {
            println!("Could not open audit log '{log_path}': {e}");
            return;
        }
    };

    let reader = BufReader::new(file);
    for line_content in reader.lines().map_while(Result::ok) {
        if let Ok(event) = serde_json::from_str::<AuditEvent>(&line_content) {
            // Simplified training logic:
            // If the action was "successful", increase utility weight.
            // If not, decrease it.
            if event.action.contains("success") {
                model.weights[1] += 0.01;
            } else {
                model.weights[1] -= 0.01;
            }
        }
    }

    // Normalize weights to sum to 1.0
    let sum = model.weights[0] + model.weights[1];
    model.weights[0] /= sum;
    model.weights[1] /= sum;

    println!("Training complete. Updated reward model:");
    println!("{model:#?}");
}
