use crate::audit_chain::ReasoningChain;
use crate::audit_store::write_chain;

pub fn persist_trace(chain: &ReasoningChain) -> Result<(), String> {
    write_chain(chain.clone())?;
    Ok(())
}
