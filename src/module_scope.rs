use serde::{Serialize, Deserialize};

/// Defines a unique execution scope in the SigilDERG runtime.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ModuleScope {
    pub user_id: String,
    pub module_id: String,
    pub session_id: String,
}

impl ModuleScope {
    pub fn label(&self) -> String {
        format!("{}::{}@{}", self.module_id, self.user_id, self.session_id)
    }
}