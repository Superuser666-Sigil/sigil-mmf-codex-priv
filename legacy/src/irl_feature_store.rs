use crate::audit_chain::ReasoningChain;

pub fn vectorize_chain(chain: &ReasoningChain) -> Result<Vec<f32>, String> {
    // Simple feature mockup: length of text fields normalized
    let vec = vec![
        chain.input.len() as f32 / 100.0,
        chain.context.len() as f32 / 100.0,
        chain.reasoning.len() as f32 / 100.0,
    ];
    Ok(vec)
}
