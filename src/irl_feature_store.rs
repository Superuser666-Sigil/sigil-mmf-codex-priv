use crate::audit_chain::ReasoningChain;

pub fn vectorize_chain(chain: &ReasoningChain) -> Result<Vec<f32>, String> {
    // Simple feature mockup: length of text fields normalized
    let mut vec = Vec::new();
    vec.push(chain.input.len() as f32 / 100.0);
    vec.push(chain.context.len() as f32 / 100.0);
    vec.push(chain.reasoning.len() as f32 / 100.0);
    Ok(vec)
}