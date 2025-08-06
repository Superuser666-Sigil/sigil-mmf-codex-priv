use crate::loa::LOA;
use crate::trusted_knowledge::TrustedKnowledgeEntry;
use serde_json::Value;
use std::fs;

pub trait CanonStore: Send + Sync {
    fn load_entry(&self, key: &str, loa: &LOA) -> Option<TrustedKnowledgeEntry>;

    fn add_entry(
        &mut self,
        entry: TrustedKnowledgeEntry,
        loa: &LOA,
        allow_operator_write: bool,
    ) -> Result<(), &'static str>;

    fn list_entries(&self, category: Option<&str>, loa: &LOA) -> Vec<TrustedKnowledgeEntry>;
}

pub fn revert_node(id: &str, to_hash: &str) -> Result<(), String> {
    // Load the current canon file
    let canon_path = "canon files/canon.json";
    let content =
        fs::read_to_string(canon_path).map_err(|e| format!("Failed to read canon file: {e}"))?;

    let mut canon: Value =
        serde_json::from_str(&content).map_err(|e| format!("Failed to parse canon JSON: {e}"))?;

    // Find the node to revert
    if let Some(entries) = canon.get_mut("entries") {
        if let Some(entries_arr) = entries.as_array_mut() {
            for entry in entries_arr.iter_mut() {
                if let Some(entry_id) = entry.get("id").and_then(|id| id.as_str()) {
                    if entry_id == id {
                        // Check if the target hash exists in version history
                        if let Some(versions) = entry.get("versions") {
                            if let Some(version_array) = versions.as_array() {
                                for version in version_array {
                                    if let Some(version_hash) =
                                        version.get("hash").and_then(|h| h.as_str())
                                    {
                                        if version_hash == to_hash {
                                            // Revert to this version
                                            if let Some(content) = version.get("content") {
                                                entry["content"] = content.clone();
                                                entry["current_hash"] =
                                                    serde_json::Value::String(to_hash.to_string());

                                                // Write back to file
                                                let updated_content = serde_json::to_string_pretty(
                                                    &canon,
                                                )
                                                .map_err(|e| {
                                                    format!("Failed to serialize canon: {e}")
                                                })?;

                                                fs::write(canon_path, updated_content).map_err(
                                                    |e| format!("Failed to write canon file: {e}"),
                                                )?;

                                                println!("✅ Successfully reverted node '{id}' to hash '{to_hash}'");
                                                return Ok(());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        return Err(format!(
                            "Target hash '{to_hash}' not found in version history for node '{id}'"
                        ));
                    }
                }
            }
        }
    }

    Err(format!("Node '{id}' not found in canon"))
}
