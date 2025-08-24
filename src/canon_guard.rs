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
        .map_err(|e| format!("Witness validation error: {e}"))? {
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
    // Look for explicit verdict in hyperparameters first
    if let Some(verdict_str) = chain.metadata.hyperparameters.get("verdict") {
        return match verdict_str.as_str() {
            "Allow" => Ok(Verdict::Allow),
            "Deny" => Ok(Verdict::Deny),
            "Defer" => Ok(Verdict::Defer),
            "ManualReview" => Ok(Verdict::ManualReview),
            _ => Err("Invalid verdict in metadata".to_string()),
        };
    }
    
    // Fallback to reasoning analysis with more sophisticated logic
    let reasoning_text = &chain.reasoning_trace.reasoning_steps
        .iter()
        .map(|step| step.logic.clone())
        .collect::<Vec<_>>()
        .join("\n");
    
    // Use more sophisticated analysis
    let verdict_score = analyze_reasoning_for_verdict(reasoning_text);
    
    match verdict_score {
        score if score > 0.8 => Ok(Verdict::Allow),
        score if score < 0.2 => Ok(Verdict::Deny),
        score if score < 0.5 => Ok(Verdict::ManualReview),
        _ => Ok(Verdict::Defer),
    }
}

/// Analyze reasoning text to determine verdict score
fn analyze_reasoning_for_verdict(reasoning_text: &str) -> f64 {
    let text = reasoning_text.to_lowercase();
    let mut score: f64 = 0.5; // Neutral starting point
    
    // Positive indicators
    let positive_keywords = [
        "allow", "permit", "approve", "accept", "valid", "safe", "trusted",
        "authorized", "legitimate", "compliant", "secure", "verified"
    ];
    
    // Negative indicators
    let negative_keywords = [
        "deny", "reject", "block", "forbid", "invalid", "unsafe", "untrusted",
        "unauthorized", "illegitimate", "non-compliant", "insecure", "unverified"
    ];
    
    // Uncertainty indicators
    let uncertainty_keywords = [
        "defer", "postpone", "review", "manual", "uncertain", "unclear",
        "ambiguous", "conflicting", "inconclusive", "needs_review"
    ];
    
    // Count positive keywords
    for keyword in &positive_keywords {
        if text.contains(keyword) {
            score += 0.1;
        }
    }
    
    // Count negative keywords
    for keyword in &negative_keywords {
        if text.contains(keyword) {
            score -= 0.1;
        }
    }
    
    // Count uncertainty keywords
    for keyword in &uncertainty_keywords {
        if text.contains(keyword) {
            score -= 0.05; // Reduce confidence but not as much as negative
        }
    }
    
    // Clamp score between 0.0 and 1.0
    score.clamp(0.0, 1.0)
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
      ).map_err(|e| format!("Witness validation error: {e}"))
}
