use crate::canon_loader::CanonNode;
use std::collections::HashMap;

/// Compute a basic semantic diff between two CanonNodes using title, tags, and trust_level
pub fn semantic_diff(a: &CanonNode, b: &CanonNode) -> HashMap<String, String> {
    let mut diffs = HashMap::new();

    if a.title != b.title {
        diffs.insert("title".into(), format!("{} -> {}", a.title, b.title));
    }

    if a.trust_level != b.trust_level {
        diffs.insert("trust_level".into(), format!("{} -> {}", a.trust_level, b.trust_level));
    }

    if a.flags != b.flags {
        diffs.insert("flags".into(), format!("{:?} -> {:?}", a.flags, b.flags));
    }

    if a.tags != b.tags {
        diffs.insert("tags".into(), format!("{:?} -> {:?}", a.tags, b.tags));
    }

    diffs
}