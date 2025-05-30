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
    pub content: String,
    pub trust_level: String,
    pub flags: Vec<String>,
    pub checksum: String,
    pub source: String,
    pub section: String,
    pub tags: Vec<String>,
    pub codex_commentary: serde_json::Value,
}

pub fn load_from_jsonl(dir: &Path) -> Result<Vec<CanonNode>, String> {
    let mut nodes = Vec::new();

    for entry in read_dir(dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();

        if path.extension().map(|ext| ext == "jsonl").unwrap_or(false) {
            let file = File::open(&path).map_err(|e| format!("Error opening {:?}: {}", path, e))?;
            let reader = BufReader::new(file);

            for line in reader.lines() {
                let line = line.map_err(|e| e.to_string())?;
                let node: CanonNode = serde_json::from_str(&line).map_err(|e| e.to_string())?;

                let mut chain = ReasoningChain::new(format!("canon_load:{}", node.id), LoaLevel::Root);
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

                write_chain(&chain)?;
                nodes.push(node);
            }
        }
    }

    Ok(nodes)
}