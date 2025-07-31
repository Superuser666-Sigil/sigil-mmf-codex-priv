use crate::canon_loader::CanonNode;
use crate::canon_validator::validate_entry;
use crate::irl_executor::evaluate_with_irl;
use crate::audit_chain::ReasoningChain;

pub fn process_canon_node_with_irl(node: &CanonNode) -> Result<f64, String> {
    // Convert CanonNode to serde_json::Value for validation
    let node_json = serde_json::to_value(node)
        .map_err(|e| format!("Failed to serialize node: {e}"))?;
    
    // Validate the node
    let result = validate_entry(&node_json);
    if let Err(e) = result {
        return Err(format!("Validation failed: {e}"));
    }
    
    // Create a reasoning chain for IRL evaluation
    let mut chain = ReasoningChain::new(
        format!("Processing canon node: {}", node.id),
        crate::loa::LoaLevel::Observer
    );
    
    // Evaluate with IRL
    let score = evaluate_with_irl(&mut chain);
    
    Ok(score)
}
