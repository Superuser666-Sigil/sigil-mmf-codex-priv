
use crate::loa::LOA;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum SigilVerdict {
    Allow,
    Deny,
    Quarantine,
    Escalate,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TrustedKnowledgeEntry {
    pub id: String,                  // Canonical UUID or key
    pub loa_required: LOA,          // Trust level needed to access
    pub verdict: SigilVerdict,      // Result if access is attempted
    pub category: String,           // 'spell', 'gear', 'metatype', etc.
    pub content: String,            // Canonical text or payload
}

impl TrustedKnowledgeEntry {
    pub fn is_valid(&self) -> bool {
        !self.id.is_empty()
            && !self.category.is_empty()
            && !self.content.is_empty()
    }

    pub fn access_verdict(&self, loa: &LOA) -> SigilVerdict {
        if loa >= &self.loa_required {
            SigilVerdict::Allow
        } else {
            self.verdict.clone()
        }
    }
}
