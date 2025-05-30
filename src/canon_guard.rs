use crate::audit_chain::{ReasoningChain, Verdict};
use crate::audit_store::write_chain;
use crate::sigil_integrity::validate_witnesses;
use crate::loa::LoaLevel;

/// Verifies that a ReasoningChain has proper authority to mutate Canon.
/// Should be called before any write or diff commit.
pub fn guard_canon_mutation(chain: &ReasoningChain, payload: &str) -> Result<(), String> {
    if chain.verdict != Verdict::Allow {
        return Err("Denied: Chain verdict is not Allow.".into());
    }

    if !chain.irl.allowed {
        return Err("Denied: IRL trust does not permit this action.".into());
    }

    if chain.audit.loa != LoaLevel::Root {
        return Err("Denied: Only Root LOA may write to Canon.".into());
    }

    if !validate_witnesses(&chain.witnesses, &LoaLevel::Root, payload) {
        return Err("Denied: Witness quorum not satisfied.".into());
    }

    if let Err(e) = write_chain(chain) {
        return Err(format!("Audit log failure: {}", e));
    }

    Ok(())
}