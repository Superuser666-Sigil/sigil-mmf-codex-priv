use std::fs::{create_dir_all, File};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use chrono::{Datelike, Local};
use crate::audit_chain::ReasoningChain;
use crate::module_scope::ModuleScope;

/// Root directory for audit log output (configurable later)
const AUDIT_DIR: &str = "./audit";

pub fn write_chain(chain: &ReasoningChain) -> Result<PathBuf, String> {
    let today = Local::now();
    let path = Path::new(AUDIT_DIR)
        .join(format!("{}", today.year()))
        .join(format!("{:02}-{:02}", today.month(), today.day()))
        .join(format!("{}.json", chain.audit.chain_id));

    if let Some(parent) = path.parent() {
        create_dir_all(parent).map_err(|e| format!("Failed to create audit dir: {}", e))?;
    }

    let file = File::create(&path).map_err(|e| format!("Failed to write audit: {}", e))?;
    let writer = BufWriter::new(file);

    serde_json::to_writer_pretty(writer, &chain)
        .map_err(|e| format!("Serialization error: {}", e))?;

    Ok(path)
}

pub fn get_chains_by_scope(scope: &ModuleScope) -> Vec<ReasoningChain> {
    let mut results = Vec::new();
    let root = Path::new(AUDIT_DIR);

    if !root.exists() {
        return results;
    }

    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.path().is_file() && e.path().extension().map(|ext| ext == "json").unwrap_or(false))
    {
        let file = File::open(entry.path()).ok()?;
        let reader = BufReader::new(file);
        let maybe_chain: Result<ReasoningChain, _> = serde_json::from_reader(reader);

        if let Ok(chain) = maybe_chain {
            if &chain.scope == scope {
                results.push(chain);
            }
        }
    }

    results
}