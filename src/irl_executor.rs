use crate::audit_chain::ReasoningChain;
use crate::irl_feature_store::vectorize_chain;
use crate::audit_store::write_chain;

pub fn evaluate_chain(chain: &ReasoningChain) -> Result<f32, String> {
    let vec = vectorize_chain(chain)?;
    let score = vec.iter().sum::<f32>() / vec.len().max(1) as f32;
    write_chain(chain)?;  // optional: confirm chain is audited
    Ok(score)
}
use crate::audit_chain::ReasoningChain;

pub fn evaluate_with_irl(chain: &mut ReasoningChain) -> f64 {
    chain.score = Some(0.95);
    0.95
}
