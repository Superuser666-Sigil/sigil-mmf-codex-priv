use crate::audit_chain::{FrozenChain, ReasoningChain};
use serde_json;
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;

/// Audit store for managing both ReasoningChain (process) and FrozenChain (immutable records)
pub struct AuditStore {
    reasoning_log_path: String,
    frozen_chain_path: String,
}

impl AuditStore {
    pub fn new(reasoning_log_path: &str, frozen_chain_path: &str) -> Self {
        // Ensure directories exist
        if let Some(parent) = Path::new(reasoning_log_path).parent() {
            let _ = create_dir_all(parent);
        }
        if let Some(parent) = Path::new(frozen_chain_path).parent() {
            let _ = create_dir_all(parent);
        }

        AuditStore {
            reasoning_log_path: reasoning_log_path.to_string(),
            frozen_chain_path: frozen_chain_path.to_string(),
        }
    }

    /// Store a ReasoningChain (mutable process) - for debugging and development
    pub fn write_reasoning_chain(&self, chain: &ReasoningChain) -> Result<(), String> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.reasoning_log_path)
            .map_err(|e| format!("Failed to open reasoning log: {e}"))?;

        let mut writer = BufWriter::new(file);
        let json = serde_json::to_string(chain)
            .map_err(|e| format!("Failed to serialize reasoning chain: {e}"))?;

        writeln!(writer, "{json}").map_err(|e| format!("Failed to write reasoning chain: {e}"))?;

        writer
            .flush()
            .map_err(|e| format!("Failed to flush reasoning chain: {e}"))?;

        Ok(())
    }

    /// Store a FrozenChain (immutable record) - for production and audit trails
    pub fn write_frozen_chain(&self, chain: &FrozenChain) -> Result<(), String> {
        // Verify integrity before storing
        if !chain.verify_integrity()? {
            return Err("Cannot store FrozenChain with invalid integrity".into());
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.frozen_chain_path)
            .map_err(|e| format!("Failed to open frozen chain log: {e}"))?;

        let mut writer = BufWriter::new(file);
        let json = serde_json::to_string(chain)
            .map_err(|e| format!("Failed to serialize frozen chain: {e}"))?;

        writeln!(writer, "{json}").map_err(|e| format!("Failed to write frozen chain: {e}"))?;

        writer
            .flush()
            .map_err(|e| format!("Failed to flush frozen chain: {e}"))?;

        Ok(())
    }

    /// Freeze a ReasoningChain and store it as a FrozenChain
    pub fn freeze_and_store_chain(&self, chain: ReasoningChain) -> Result<FrozenChain, String> {
        // First, finalize the reasoning
        let mut finalized_chain = chain;
        finalized_chain.finalize_reasoning()?;

        // Freeze the chain
        let frozen_chain = FrozenChain::freeze_reasoning_chain(finalized_chain)?;

        // Store the frozen chain
        self.write_frozen_chain(&frozen_chain)?;

        Ok(frozen_chain)
    }

    /// Retrieve a FrozenChain by ID
    pub fn get_frozen_chain(&self, chain_id: &str) -> Result<Option<FrozenChain>, String> {
        let file = File::open(&self.frozen_chain_path)
            .map_err(|e| format!("Failed to open frozen chain log: {e}"))?;

        let reader = std::io::BufReader::new(file);
        let lines = std::io::BufRead::lines(reader);

        for line in lines {
            let line = line.map_err(|e| format!("Failed to read line: {e}"))?;
            let chain: FrozenChain = serde_json::from_str(&line)
                .map_err(|e| format!("Failed to parse frozen chain: {e}"))?;

            if chain.chain_id == chain_id {
                // Verify integrity on retrieval
                if !chain.verify_integrity()? {
                    return Err("Retrieved FrozenChain failed integrity verification".into());
                }
                return Ok(Some(chain));
            }
        }

        Ok(None)
    }

    /// Get all FrozenChains in lineage order
    pub fn get_chain_lineage(&self, chain_id: &str) -> Result<Vec<FrozenChain>, String> {
        let mut chains = Vec::new();
        let mut current_chain_id = chain_id.to_string();

        while let Some(chain) = self.get_frozen_chain(&current_chain_id)? {
            chains.push(chain.clone());

            // Get the first parent (assuming linear lineage for now)
            if let Some(parent_id) = chain.parent_chain_ids.first() {
                current_chain_id = parent_id.clone();
            } else {
                break;
            }
        }

        // Reverse to get chronological order
        chains.reverse();
        Ok(chains)
    }

    /// Verify the integrity of all stored FrozenChains
    pub fn verify_all_integrity(&self) -> Result<Vec<String>, String> {
        let mut failed_chains = Vec::new();
        let file = File::open(&self.frozen_chain_path)
            .map_err(|e| format!("Failed to open frozen chain log: {e}"))?;

        let reader = std::io::BufReader::new(file);
        let lines = std::io::BufRead::lines(reader);

        for (line_num, line) in lines.enumerate() {
            let line = line.map_err(|e| format!("Failed to read line {}: {}", line_num + 1, e))?;

            match serde_json::from_str::<FrozenChain>(&line) {
                Ok(chain) => {
                    if !chain.verify_integrity()? {
                        failed_chains.push(format!(
                            "Chain {} at line {} failed integrity check",
                            chain.chain_id,
                            line_num + 1
                        ));
                    }
                }
                Err(e) => {
                    failed_chains.push(format!(
                        "Failed to parse chain at line {}: {}",
                        line_num + 1,
                        e
                    ));
                }
            }
        }

        Ok(failed_chains)
    }
}

// Legacy function for backward compatibility
pub fn write_chain(chain: ReasoningChain) -> Result<String, String> {
    let store = AuditStore::new("logs/reasoning_chains.jsonl", "logs/frozen_chains.jsonl");
    let frozen_chain = FrozenChain::freeze_reasoning_chain(chain)?;
    store.write_frozen_chain(&frozen_chain)?;
    Ok(frozen_chain.chain_id)
}
