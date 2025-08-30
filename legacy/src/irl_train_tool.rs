use crate::audit_chain::{FrozenChain, ReasoningChain, Verdict};
use crate::audit_store::AuditStore;
use crate::loa::{enforce, LoaLevel};

/// Entry point for the Sigil IRL training pipeline.
/// Under Rule Zero, this implementation logs intent and denies untrusted execution.
/// Demonstrates the two-phase approach: ReasoningChain -> FrozenChain
pub fn train_model(user_loa: LoaLevel, trace_path: &str) -> Result<(), String> {
    // Enforce only `Root` can initiate training
    enforce(LoaLevel::Root, user_loa.clone())?;

    // Phase 1: Create ReasoningChain (mutable process)
    let mut chain = ReasoningChain::new("train_model", user_loa);
    chain.add_context(format!("Requested training from trace: {trace_path}"));
    chain.add_reasoning_step("IRL model training is not yet implemented.");
    chain.add_reasoning_step("Execution is denied to prevent untrusted learning.");
    chain.add_reasoning_step("This ensures Rule Zero compliance.");
    chain.add_suggestion("Defer this command until IRL executor and feature store are available.");
    chain.set_verdict(Verdict::Deny);
    chain.set_irl_score(0.0, false);

    // Finalize the reasoning process
    chain.finalize_reasoning()?;

    // Phase 2: Freeze into immutable FrozenChain
    let store = AuditStore::new("logs/reasoning_chains.jsonl", "logs/frozen_chains.jsonl");
    let frozen_chain = store.freeze_and_store_chain(chain)?;

    // Verify the frozen chain integrity
    if !frozen_chain.verify_integrity()? {
        return Err("FrozenChain integrity verification failed".into());
    }

    println!("✅ Training request processed and frozen:");
    println!("   Chain ID: {}", frozen_chain.chain_id);
    println!("   Frozen at: {}", frozen_chain.frozen_at);
    println!("   Content hash: {}", &frozen_chain.content_hash[..16]);

    Err("IRL model training not implemented yet".into())
}

/// Demonstrate the two-phase approach with a simple reasoning example
pub fn demonstrate_reasoning_chain_to_frozen_chain() -> Result<FrozenChain, String> {
    // Phase 1: ReasoningChain - "thinking out loud"
    let mut chain = ReasoningChain::new("What is 3 + 4?", LoaLevel::Root);
    chain.add_context("Mathematical reasoning context");
    chain.add_reasoning_step("I start with 3");
    chain.add_reasoning_step("I add 4 more");
    chain.add_reasoning_step("3 + 4 = 7");
    chain.add_suggestion("The answer is 7");
    chain.set_verdict(Verdict::Allow);
    chain.set_irl_score(0.95, true);

    // Finalize the reasoning
    chain.finalize_reasoning()?;

    // Phase 2: Freeze into immutable record
    let store = AuditStore::new("logs/reasoning_chains.jsonl", "logs/frozen_chains.jsonl");
    let frozen_chain = store.freeze_and_store_chain(chain)?;

    println!("✅ Reasoning chain frozen successfully:");
    println!("   Input: {}", frozen_chain.input_snapshot.raw_input);
    println!("   Output: {}", frozen_chain.output_snapshot.final_output);
    println!("   Chain ID: {}", frozen_chain.chain_id);
    println!(
        "   Integrity verified: {}",
        frozen_chain.verify_integrity()?
    );

    Ok(frozen_chain)
}

/// Retrieve and verify a frozen chain
pub fn retrieve_and_verify_chain(chain_id: &str) -> Result<FrozenChain, String> {
    let store = AuditStore::new("logs/reasoning_chains.jsonl", "logs/frozen_chains.jsonl");

    match store.get_frozen_chain(chain_id)? {
        Some(chain) => {
            println!("✅ Retrieved frozen chain:");
            println!("   Chain ID: {}", chain.chain_id);
            println!("   Input: {}", chain.input_snapshot.raw_input);
            println!("   Output: {}", chain.output_snapshot.final_output);
            println!("   Integrity verified: {}", chain.verify_integrity()?);
            Ok(chain)
        }
        None => Err(format!("FrozenChain with ID {chain_id} not found")),
    }
}

/// Get the lineage of a chain
pub fn get_chain_lineage(chain_id: &str) -> Result<Vec<FrozenChain>, String> {
    let store = AuditStore::new("logs/reasoning_chains.jsonl", "logs/frozen_chains.jsonl");
    let lineage = store.get_chain_lineage(chain_id)?;

    println!("📋 Chain lineage for {chain_id}:");
    for (i, chain) in lineage.iter().enumerate() {
        println!(
            "   {}: {} (frozen at {})",
            i + 1,
            chain.chain_id,
            chain.frozen_at
        );
    }

    Ok(lineage)
}
