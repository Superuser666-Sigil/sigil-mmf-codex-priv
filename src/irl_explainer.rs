use crate::audit_chain::ReasoningChain;

pub fn explain_score(chain: &ReasoningChain, score: f32) -> String {
    format!(
        "Based on {} reasoning tokens and {} context tokens, the score {:.2} reflects moderate trust.",
        chain.reasoning.len(),
        chain.context.len(),
        score
    )
}