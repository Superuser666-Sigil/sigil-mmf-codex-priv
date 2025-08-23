//! RPC protocol definitions for Sigil.
//!
//! This module implements a minimal [JSON-RPC 2.0](https://www.jsonrpc.org/specification)
//! schema using `serde` for serialization. The data structures are shared by
//! both clients and servers to ensure compatibility.
//!
//! # Examples
//!
//! ```
//! use mmf_sigil::proto::rpc::{RpcRequest, RpcResponse};
//! use serde_json::json;
//!
//! let request = RpcRequest {
//!     jsonrpc: "2.0".into(),
//!    method: "ping".into(),
//!     params: Some(json!(["hello"])),
//!     id: Some(json!(1)),
//! };
//! let serialized = serde_json::to_string(&request).unwrap();
//! assert_eq!(serialized, r#"{"jsonrpc":"2.0","method":"ping","params":["hello"],"id":1}"#);
//! let round_trip: RpcRequest = serde_json::from_str(&serialized).unwrap();
//! assert_eq!(round_trip, request);
//!
//! let response = RpcResponse {
//!     jsonrpc: "2.0".into(),
//!     result: Some(json!("pong")),
//!     error: None,
//!     id: Some(json!(1)),
//! };
//! let serialized = serde_json::to_string(&response).unwrap();
//! assert_eq!(serialized, r#"{"jsonrpc":"2.0","result":"pong","id":1}"#);
//! let round_trip: RpcResponse = serde_json::from_str(&serialized).unwrap();
//! assert_eq!(round_trip, response);
//! ```
//!
//! The tests in this module perform similar round‑trip checks to guard against
//! schema regressions.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A JSON-RPC request message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcRequest {
    /// JSON-RPC protocol version. Should always be "2.0".
    pub jsonrpc: String,
    /// The method to invoke on the server.
    pub method: String,
    /// Optional parameters for the method.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    /// Identifier established by the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
}

/// A JSON-RPC response message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcResponse {
    /// JSON-RPC protocol version. Should always be "2.0".
    pub jsonrpc: String,
    /// Result returned on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error information if the call failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
    /// Identifier from the corresponding request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
}

/// Details about a JSON-RPC error.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcError {
    /// Error code as defined by the JSON-RPC spec.
    pub code: i32,
    /// A short description of the error.
    pub message: String,
    /// Additional data describing the error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn request_round_trip() {
        let request = RpcRequest {
            jsonrpc: "2.0".into(),
            method: "ping".into(),
            params: Some(json!(["hello"])),
            id: Some(json!(1)),
        };
        let serialized = serde_json::to_string(&request).unwrap();
        assert_eq!(
            serialized,
            r#"{"jsonrpc":"2.0","method":"ping","params":["hello"],"id":1}"#
        );
        let deserialized: RpcRequest = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, request);
    }

    #[test]
    fn response_round_trip() {
        let response = RpcResponse {
            jsonrpc: "2.0".into(),
            result: Some(json!("pong")),
            error: None,
            id: Some(json!(1)),
        };
        let serialized = serde_json::to_string(&response).unwrap();
        assert_eq!(serialized, r#"{"jsonrpc":"2.0","result":"pong","id":1}"#);
        let deserialized: RpcResponse = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, response);
    }
}
