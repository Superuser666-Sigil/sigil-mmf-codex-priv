use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::Path;
use chrono::Utc;
use serde_json::to_string_pretty;

use crate::audit_chain::ReasoningChain;

pub fn log_telemetry(chain: &ReasoningChain) -> std::io::Result<()> {
    let dir = Path::new("telemetry");
    create_dir_all(dir)?;
    let timestamp = Utc::now().timestamp();
    let path = dir.join(format!("{}.json", timestamp));
    let mut file = File::create(path)?;
    let data = to_string_pretty(chain).unwrap();
    file.write_all(data.as_bytes())?;
    Ok(())
}