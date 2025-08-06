use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleScope {
    pub user_id: String,
    pub module_id: String,
    pub session_id: String,
}

impl ModuleScope {
    pub fn new(user_id: &str, module_id: &str, session_id: &str) -> Self {
        ModuleScope {
            user_id: user_id.to_string(),
            module_id: module_id.to_string(),
            session_id: session_id.to_string(),
        }
    }
}
