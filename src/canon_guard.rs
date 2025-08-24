use crate::audit_chain::{FrozenChain, ReasoningChain, Verdict};
use crate::audit_store::AuditStore;
use crate::sigil_integrity::validate_witnesses;

/// Verifies that a ReasoningChain has proper authority to mutate Canon.
/// Should be called before any write or diff commit.
pub fn guard_canon_mutation(
    mut chain: ReasoningChain,
    payload: &str,
) -> Result<FrozenChain, String> {
    if chain.verdict != Verdict::Allow {
        return Err("Denied: Chain verdict is not Allow.".into());
    }

    if !validate_witnesses(&chain.witnesses, &crate::loa::LOA::Root, payload)
        .map_err(|e| format!("Witness validation error: {}", e))? {
        return Err("Denied: Witness validation failed.".into());
    }

    chain.finalize_reasoning()?;
    FrozenChain::freeze_reasoning_chain(chain)
}

/// Verifies that a FrozenChain has proper authority to mutate Canon.
/// This is the preferred method for production use.
pub fn guard_canon_mutation_frozen(chain: &FrozenChain, payload: &str) -> Result<(), String> {
    // Verify chain integrity
    if !chain.verify_integrity()? {
        return Err("Denied: FrozenChain integrity verification failed.".into());
    }

    // Check if the reasoning trace indicates Allow verdict
    // (We'll need to extract this from the reasoning trace)
    let verdict = extract_verdict_from_frozen_chain(chain)?;
    if verdict != Verdict::Allow {
        return Err("Denied: FrozenChain verdict is not Allow.".into());
    }

    // Verify witnesses
    if !validate_frozen_chain_witnesses(chain, payload)? {
        return Err("Denied: FrozenChain witness validation failed.".into());
    }

    // Store the frozen chain (it's already immutable)
    let store = AuditStore::new("logs/reasoning_chains.jsonl", "logs/frozen_chains.jsonl");
    store.write_frozen_chain(chain)?;

    Ok(())
}

/// Freeze a ReasoningChain and then guard canon mutation
/// This is the recommended workflow: process -> freeze -> verify -> store
pub fn freeze_and_guard_canon_mutation(
    chain: ReasoningChain,
    payload: &str,
) -> Result<FrozenChain, String> {
    // First, finalize the reasoning
    let mut finalized_chain = chain;
    finalized_chain.finalize_reasoning()?;

    // Freeze the chain
    let frozen_chain = FrozenChain::freeze_reasoning_chain(finalized_chain)?;

    // Guard the frozen chain
    guard_canon_mutation_frozen(&frozen_chain, payload)?;

    Ok(frozen_chain)
}

/// Extract verdict from a FrozenChain's reasoning trace
fn extract_verdict_from_frozen_chain(chain: &FrozenChain) -> Result<Verdict, String> {
    // For now, we'll look at the reasoning steps to determine the verdict
    // This is a simplified implementation - in practice, you'd want to store
    // the verdict explicitly in the FrozenChain structure

    let reasoning_text = &chain
        .reasoning_trace
        .reasoning_steps
        .iter()
        .map(|step| step.logic.clone())
        .collect::<Vec<_>>()
        .join("\n");

    // Simple heuristic: look for keywords in the reasoning
    if reasoning_text.to_lowercase().contains("allow")
        || reasoning_text.to_lowercase().contains("permit")
    {
        Ok(Verdict::Allow)
    } else if reasoning_text.to_lowercase().contains("deny")
        || reasoning_text.to_lowercase().contains("reject")
    {
        Ok(Verdict::Deny)
    } else if reasoning_text.to_lowercase().contains("defer")
        || reasoning_text.to_lowercase().contains("postpone")
    {
        Ok(Verdict::Defer)
    } else {
        Ok(Verdict::ManualReview)
    }
}

/// Validate witnesses for a FrozenChain
fn validate_frozen_chain_witnesses(chain: &FrozenChain, payload: &str) -> Result<bool, String> {
    let witnesses: Vec<crate::sigil_integrity::WitnessSignature> = chain
        .witnesses
        .iter()
        .map(|w| crate::sigil_integrity::WitnessSignature {
            witness_id: w.witness_id.clone(),
            signature: w.signature.clone(),
        })
        .collect();
          validate_witnesses(
          &witnesses,
          &crate::loa::LOA::Root,
          payload,
      ).map_err(|e| format!("Witness validation error: {}", e))
}
