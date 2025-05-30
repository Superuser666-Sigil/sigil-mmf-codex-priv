use crate::audit_chain::{ReasoningChain, Verdict};
use crate::loa::{enforce, LoaLevel};

/// Entry point for the Sigil IRL training pipeline.
/// Under Rule Zero, this implementation logs intent and denies untrusted execution.
pub fn train_model(user_loa: LoaLevel, trace_path: &str) -> Result<(), String> {
    // Enforce only `Root` can initiate training
    enforce(LoaLevel::Root, user_loa)?;

    let mut chain = ReasoningChain::new("train_model", user_loa);
    chain.add_context(format!("Requested training from trace: {}", trace_path));
    chain.add_reasoning("IRL model training is not yet implemented. Execution is denied to prevent untrusted learning.");
    chain.add_suggestion("Defer this command until IRL executor and feature store are available.");
    chain.set_verdict(Verdict::Deny);
    chain.set_irl_score(0.0, false);
    chain.finalize()?;

    Err("IRL model training not implemented yet".into())
}