use crate::loa::LOA;
use crate::trusted_knowledge::TrustedKnowledgeEntry;
use crate::secure_file_ops::SecureFileOperations;
use serde_json::Value;

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
    // Initialize secure file operations
    let secure_file_ops = SecureFileOperations::new(
        vec!["canon files".to_string()], 
        1024 * 1024 // 1MB max file size
    ).map_err(|e| format!("Failed to initialize secure file operations: {e}"))?;
    
    // Load the current canon file securely
    let canon_path = "canon files/canon.json";
    let content_bytes = secure_file_ops.read_file_secure(
        std::path::Path::new(canon_path)
    ).map_err(|e| format!("Failed to read canon file securely: {e}"))?;
    
    let content = String::from_utf8(content_bytes)
        .map_err(|e| format!("Failed to parse canon file content: {e}"))?;

    let mut canon: Value =
        serde_json::from_str(&content).map_err(|e| format!("Failed to parse canon JSON: {e}"))?;

    // Find the node to revert
    if let Some(entries) = canon.get_mut("entries")
        && let Some(entries_arr) = entries.as_array_mut() {
        for entry in entries_arr.iter_mut() {
            if let Some(entry_id) = entry.get("id").and_then(|id| id.as_str())
                && entry_id == id {
                // Check if the target hash exists in version history
                if let Some(versions) = entry.get("versions")
                    && let Some(version_array) = versions.as_array() {
                    for version in version_array {
                        if let Some(version_hash) =
                            version.get("hash").and_then(|h| h.as_str())
                            && version_hash == to_hash {
                            // Revert to this version
                            if let Some(content) = version.get("content") {
                                entry["content"] = content.clone();
                                entry["current_hash"] =
                                    serde_json::Value::String(to_hash.to_string());

                                // Write back to file securely
                                let updated_content = serde_json::to_string_pretty(
                                    &canon,
                                )
                                .map_err(|e| {
                                    format!("Failed to serialize canon: {e}")
                                })?;

                                secure_file_ops.write_file_secure(
                                    std::path::Path::new(canon_path),
                                    updated_content.as_bytes()
                                ).map_err(|e| format!("Failed to write canon file securely: {e}"))?;

                                println!("✅ Successfully reverted node '{id}' to hash '{to_hash}'");
                                return Ok(());
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

    Err(format!("Node '{id}' not found in canon"))
}
