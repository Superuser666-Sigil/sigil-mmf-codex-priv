
use crate::loa::{LOA, can_read_canon, can_write_canon};
use crate::trusted_knowledge::TrustedKnowledgeEntry;

pub trait CanonStore {
    fn load_entry(&self, key: &str, loa: &LOA) -> Option<TrustedKnowledgeEntry>;

    fn add_entry(&mut self, entry: TrustedKnowledgeEntry, loa: &LOA, allow_operator_write: bool) -> Result<(), &'static str>;

    fn list_entries(&self, category: Option<&str>, loa: &LOA) -> Vec<TrustedKnowledgeEntry>;
}
