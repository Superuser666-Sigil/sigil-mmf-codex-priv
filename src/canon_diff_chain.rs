use crate::canon_loader::CanonNode;
use std::collections::HashMap;
use std::fs;

/// Compute a basic semantic diff between two CanonNodes using title, tags, and trust_level
pub fn semantic_diff(a: &CanonNode, b: &CanonNode) -> HashMap<String, String> {
    let mut diffs = HashMap::new();

    if a.title != b.title {
        diffs.insert("title".into(), format!("{} -> {}", a.title, b.title));
    }

    if a.trust_level != b.trust_level {
        diffs.insert(
            "trust_level".into(),
            format!("{} -> {}", a.trust_level, b.trust_level),
        );
    }

    if a.flags != b.flags {
        diffs.insert("flags".into(), format!("{:?} -> {:?}", a.flags, b.flags));
    }

    if a.tags != b.tags {
        diffs.insert("tags".into(), format!("{:?} -> {:?}", a.tags, b.tags));
    }

    diffs
}

pub fn diff_by_id(id: &str) -> Result<HashMap<String, String>, String> {
    // Load current canon entries
    let current_entries = crate::canon_loader::load_canon_entries("canon files/canon.json")?;

    // Find the specified node
    let current_node = current_entries
        .iter()
        .find(|node| node.id == id)
        .ok_or_else(|| format!("Node with ID '{id}' not found in current canon"))?;

    // Try to load previous version from backup
    let backup_path = format!("canon files/backup/canon_{id}.json");
    let previous_entries = match fs::read_to_string(&backup_path) {
        Ok(content) => {
            let json: serde_json::Value = serde_json::from_str(&content)
                .map_err(|e| format!("Failed to parse backup JSON: {e}"))?;

            let mut nodes = Vec::new();
            if let Some(entries) = json.get("entries")
                && let Some(entries_array) = entries.as_array() {
                for entry in entries_array {
                    if let Ok(node) = CanonNode::from_json(entry) {
                        nodes.push(node);
                    }
                }
            }
            nodes
        }
        Err(_) => {
            // No backup found, return empty diff
            return Ok(HashMap::new());
        }
    };

    // Find the previous version of the node
    let previous_node = previous_entries.iter().find(|node| node.id == id);

    match previous_node {
        Some(prev) => {
            // Compute diff between previous and current
            let diffs = semantic_diff(prev, current_node);
            println!("Found {} differences for node '{}'", diffs.len(), id);
            Ok(diffs)
        }
        None => {
            // No previous version found
            println!("No previous version found for node '{id}'");
            Ok(HashMap::new())
        }
    }
}
