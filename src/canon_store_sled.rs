pub struct CanonStoreSled;

impl CanonStoreSled {
    pub fn new() -> Self {
        CanonStoreSled
    }
}

use crate::canon_store::CanonStore;
use crate::audit_chain::ReasoningChain;
use crate::canon_loader::CanonNode;

impl CanonStore for CanonStoreSled {
    fn add_entry(&mut self, node: CanonNode, chain: &ReasoningChain) -> Result<(), String> {
        self.db.insert(node.id.as_bytes(), serde_json::to_vec(&node).unwrap())
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}
