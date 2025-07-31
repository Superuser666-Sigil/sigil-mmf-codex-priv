
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Read;
use crate::trusted_knowledge::TrustedKnowledgeEntry;

#[derive(Debug, Serialize, Deserialize)]
pub struct SealedCanonEntry {
    pub entry: TrustedKnowledgeEntry,
    pub sha256: String,
}

pub fn seal_file(path: &str, out_path: &str) -> Result<(), &'static str> {
    let mut file = File::open(path).map_err(|_| "Cannot open canon file")?;
    let mut content = String::new();
    file.read_to_string(&mut content).map_err(|_| "Read error")?;

    let entry: TrustedKnowledgeEntry = serde_json::from_str(&content).map_err(|_| "Parse error")?;
    let hash = Sha256::digest(content.as_bytes());
    let sealed = SealedCanonEntry {
        entry,
        sha256: format!("{hash:x}"),
    };

    let out_json = serde_json::to_string_pretty(&sealed).map_err(|_| "Serialization error")?;
    fs::write(out_path, out_json).map_err(|_| "Write failed")?;
    Ok(())
}

use crate::canon_loader::CanonNode;

pub fn seal_canon_entry(node: &CanonNode) -> String {
    format!("sealed:{}", node.id)
}
