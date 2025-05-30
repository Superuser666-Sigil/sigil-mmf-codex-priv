use crate::audit_chain::{ReasoningChain, Verdict};
use crate::audit_store::write_chain;
use crate::loa::LoaLevel;

pub fn get_mode(chain: &mut ReasoningChain) -> &'static str {
    chain.add_context("Checked runtime IRL mode");
    chain.add_reasoning("Trust enforcement currently operates in passive mode only.");
    chain.add_suggestion("Return mode as 'passive'");
    chain.set_verdict(Verdict::Allow);
    chain.set_irl_score(0.0, true);
    let _ = write_chain(chain);
    "passive"
}