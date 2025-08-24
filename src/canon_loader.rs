use std::fs::{read_dir, File};
use std::io::{BufRead, BufReader};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::audit_chain::{ReasoningChain, Verdict};
use crate::audit_store::write_chain;
use crate::loa::LoaLevel;
use crate::module_scope::ModuleScope;
use crate::sigil_integrity::WitnessSignature;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonNode {
    pub id: String,
    pub title: String,
    pub trust_level: String,
    pub flags: Vec<String>,
    pub tags: Vec<String>,
    pub content: serde_json::Value,
    pub codex_commentary: serde_json::Value,
}

impl CanonNode {
    pub fn new(id: &str, title: &str, trust_level: &str) -> Self {
        CanonNode {
            id: id.to_string(),
            title: title.to_string(),
            trust_level: trust_level.to_string(),
            flags: Vec::new(),
            tags: Vec::new(),
            content: serde_json::Value::Null,
            codex_commentary: serde_json::Value::Null,
        }
    }

    pub fn from_json(json: &serde_json::Value) -> Result<Self, String> {
        let id = json
            .get("id")
            .and_then(|id| id.as_str())
            .ok_or("Missing 'id' field")?;

        let title = json
            .get("name")
            .and_then(|name| name.as_str())
            .unwrap_or("Untitled");

        let trust_level = json
            .get("trust_level")
            .and_then(|tl| tl.as_str())
            .unwrap_or("unverified");

        let mut node = CanonNode::new(id, title, trust_level);

        // Parse flags if present
        if let Some(flags) = json.get("flags")
            && let Some(flags_array) = flags.as_array() {
            for flag in flags_array {
                if let Some(flag_str) = flag.as_str() {
                    node.flags.push(flag_str.to_string());
                }
            }
        }

        // Parse tags if present
        if let Some(tags) = json.get("tags")
            && let Some(tags_array) = tags.as_array() {
            for tag in tags_array {
                if let Some(tag_str) = tag.as_str() {
                    node.tags.push(tag_str.to_string());
                }
            }
        }

        Ok(node)
    }
}

pub fn load_from_jsonl(dir: &Path) -> Result<Vec<CanonNode>, String> {
    let mut nodes = Vec::new();

    for entry in read_dir(dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();

        if path.extension().map(|ext| ext == "jsonl").unwrap_or(false) {
            let file = File::open(&path).map_err(|e| format!("Error opening {path:?}: {e}"))?;
            let reader = BufReader::new(file);

            for line in reader.lines() {
                let line = line.map_err(|e| e.to_string())?;
                let node: CanonNode = serde_json::from_str(&line).map_err(|e| e.to_string())?;

                let mut chain =
                    ReasoningChain::new(format!("canon_load:{}", node.id), LoaLevel::Root);
                chain.set_verdict(Verdict::Allow);
                chain.set_irl_score(1.0, true);
                chain.set_scope(ModuleScope {
                    user_id: "bootstrap".into(),
                    module_id: "canon_loader".into(),
                    session_id: "init".into(),
                });

                chain.add_context("Loading CanonNode from JSONL during seed.");
                chain.add_reasoning("This node is pre-trusted from a signed Canon source.");
                chain.add_suggestion("Admit node into Canon memory space.");
                chain.set_witnesses(vec![
                    WitnessSignature {
                        witness_id: "sigil_init_loader".into(),
                        signature: "FAKE_SIG_BOOTSTRAP".into(),
                    },
                    WitnessSignature {
                        witness_id: "root_mnemonic".into(),
                        signature: "FAKE_SIG_MNEMONIC".into(),
                    },
                    WitnessSignature {
                        witness_id: "first_trust_agent".into(),
                        signature: "FAKE_SIG_AGENT".into(),
                    },
                ]);

                write_chain(chain)?;
                nodes.push(node);
            }
        }
    }

    Ok(nodes)
}

// Missing function that is referenced in other modules
pub fn load_canon_entries(file: &str) -> Result<Vec<CanonNode>, String> {
    let content = std::fs::read_to_string(file)
        .map_err(|e| format!("Failed to read canon file '{file}': {e}"))?;

    let json: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse canon JSON from '{file}': {e}"))?;

    let mut nodes = Vec::new();

    if let Some(entries) = json.get("entries")
        && let Some(entries_array) = entries.as_array() {
        for entry in entries_array {
            if let Ok(node) = CanonNode::from_json(entry) {
                nodes.push(node);
            } else {
                println!("Warning: Failed to parse canon entry: {entry:?}");
            }
        }
    }

    println!("Loaded {} canon entries from '{}'", nodes.len(), file);
    Ok(nodes)
}
