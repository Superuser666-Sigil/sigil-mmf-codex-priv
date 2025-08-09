use crate::loa::LOA;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMemoryBlock {
    pub id: String,
    pub session_id: String,
    pub mnemonic: Option<String>,
    pub loa: LOA,
    pub content: String,
    pub deleted: bool,
}

impl VaultMemoryBlock {
    pub fn new(id: &str, session_id: &str, loa: LOA, content: &str) -> Self {
        VaultMemoryBlock {
            id: id.to_string(),
            session_id: session_id.to_string(),
            mnemonic: None,
            loa,
            content: content.to_string(),
            deleted: false,
        }
    }
}
