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
    let payload = IRLQuery {
        context: context.into(),
        input: input.into(),
    };

    let res = client
        .post("http://localhost:11434/irl")  // ← Change if your Phi-4 endpoint is different
        .json(&payload)
        .send()?
        .error_for_status()?;

    let parsed: IRLResponse = res.json()?;
    Ok(parsed)
}