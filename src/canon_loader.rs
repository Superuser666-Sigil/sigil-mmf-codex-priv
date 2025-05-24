use crate::trusted_knowledge::TrustedKnowledgeEntry;
use std::fs::File;
use std::io::{BufReader, BufRead};
use serde_json::from_str;
use log::error;

pub fn load_canon_entries(path: &str) -> Result<Vec<TrustedKnowledgeEntry>, String> {
    let file = File::open(path).map_err(|e| format!("Failed to open Canon file: {}", e))?;
    let reader = BufReader::new(file);

    let mut entries = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        match line {
            Ok(json_line) => {
                match from_str::<TrustedKnowledgeEntry>(&json_line) {
                    Ok(entry) => entries.push(entry),
                    Err(e) => {
                        error!("Failed to parse entry at line {}: {}", index + 1, e);
                        return Err(format!("Invalid entry at line {}: {}", index + 1, e));
                    }
                }
            }
            Err(e) => return Err(format!("Error reading line {}: {}", index + 1, e)),
        }
    }

    Ok(entries)
}
