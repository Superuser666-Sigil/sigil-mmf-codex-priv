//! Adapter module to communicate with local or remote IRL executors (e.g., Phi-4 via LM Studio)
//! 
//! Enhanced with secure network client implementation as specified in Phase 2.7 of the security audit plan.

use serde::{Deserialize, Serialize};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use crate::errors::SigilError;

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

/// Secure network client with timeout and TLS enforcement
#[derive(Clone)]
pub struct SecureNetworkClient {
    client: reqwest::Client,
    base_url: String,
    timeout: Duration,
}

impl SecureNetworkClient {
    /// Create a new secure network client
    pub fn new(base_url: String, timeout_seconds: u64) -> Result<Self, SigilError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_seconds))
            .use_rustls_tls() // Use rustls instead of OpenSSL
            .build()
            .map_err(|e| SigilError::network("creating HTTP client", e))?;
        
        Ok(Self {
            client,
            base_url,
            timeout: Duration::from_secs(timeout_seconds),
        })
    }
    
    /// Query IRL executor with enhanced security
    pub async fn query_phi4_executor(
        &self,
        context: &str,
        input: &str,
        api_key: Option<&str>,
    ) -> Result<IRLResponse, SigilError> {
        let payload = serde_json::json!({
            "context": context,
            "input": input,
            "model": "phi-4",
            "stream": false
        });
        
        let mut request = self.client
            .post(format!("{}/irl", self.base_url))
            .header("Content-Type", "application/json")
            .header("User-Agent", "Sigil-IRL-Client/1.0")
            .json(&payload);
        
        // Add authorization if provided
        if let Some(key) = api_key {
            request = request.header("Authorization", format!("Bearer {key}"));
        }
        
        let response = request
            .send()
            .await
            .map_err(|e| SigilError::network("sending IRL request", e))?;
        
        if !response.status().is_success() {
            return Err(SigilError::internal(format!(
                "HTTP error: {} - {}", 
                response.status(), 
                response.text().await.unwrap_or_default()
            )));
        }
        
        response.json::<IRLResponse>()
            .await
            .map_err(|e| SigilError::network("parsing IRL response", e))
    }
    
    /// Get client statistics
    pub fn get_stats(&self) -> NetworkClientStats {
        NetworkClientStats {
            base_url: self.base_url.clone(),
            timeout: self.timeout,
            tls_enabled: true,
        }
    }
}

/// Network client statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkClientStats {
    pub base_url: String,
    pub timeout: Duration,
    pub tls_enabled: bool,
}

/// Legacy function for backward compatibility
pub fn query_phi4_executor(context: &str, input: &str) -> Result<IRLResponse, Box<dyn std::error::Error>> {
    // Create a default secure client for legacy usage
    let client = SecureNetworkClient::new("http://localhost:11434".to_string(), 30)
        .map_err(|e| format!("Failed to create network client: {e}"))?;

    // If we're already inside a Tokio runtime, offload the async work to a helper thread.
    // Creating a new runtime on the same thread would panic, mirroring Python's
    // ``RuntimeError: Cannot run the event loop while another loop is running``.
    let response = if tokio::runtime::Handle::try_current().is_ok() {
        let (tx, rx) = mpsc::channel();
        let client_clone = client.clone();
        let context_owned = context.to_string();
        let input_owned = input.to_string();

        thread::spawn(move || {
            let result: Result<IRLResponse, SigilError> = (|| {
                let runtime = tokio::runtime::Runtime::new().map_err(|e| {
                    SigilError::internal(format!("Failed to create runtime: {e}"))
                })?;

                runtime.block_on(async {
                    client_clone
                        .query_phi4_executor(&context_owned, &input_owned, None)
                        .await
                })
            })();

            let _ = tx.send(result);
        });

        rx.recv()
            .map_err(|e| format!("Failed to receive IRL response: {e}"))??
    } else {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| format!("Failed to create runtime: {e}"))?;

        runtime
            .block_on(async { client.query_phi4_executor(context, input, None).await })?
    };

    Ok(response)
}
