//! Adapter module to communicate with local or remote IRL executors (e.g., Phi-4 via LM Studio)

use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Debug, Serialize)]
pub struct IRLQuery {
    pub context: String,
    pub input: String,
}

#[derive(Debug, Deserialize)]
pub struct IRLResponse {
    pub model_id: String,
    pub score: f32,
    pub allowed: bool,
}

pub fn query_phi4_executor(context: &str, input: &str) -> Result<IRLResponse, Box<dyn Error>> {
    let client = reqwest::blocking::Client::new();
    let payload = serde_json::json!({
        "context": context,
        "input": input,
        "model": "phi-4",
        "stream": false
    });

    let res = client
        .post("http://localhost:11434/irl") // ← Change if your Phi-4 endpoint is different
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&payload).unwrap())
        .send()?;

    let parsed = res.json::<IRLResponse>()?;
    Ok(parsed)
}
