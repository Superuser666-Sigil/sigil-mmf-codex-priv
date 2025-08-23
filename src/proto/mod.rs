//! RPC and protocol buffer schema definitions.
//!
//! Currently this module exposes a minimal [JSON-RPC 2.0](https://www.jsonrpc.org/)
//! interface used for communication between Sigil components. Additional
//! protocol types may be added in the future as requirements expand.

pub mod rpc;

pub use rpc::{RpcError, RpcRequest, RpcResponse};
