//! Comprehensive error handling for the Sigil Runtime
//!
//! This module provides structured error types following Rust best practices
//! as outlined in The Rust Book Chapter 9 on Error Handling.

use crate::loa::LOA;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

/// Main error type for the Sigil Runtime system
///
/// Following The Rust Book's guidance on custom error types,
/// this enum covers all major error categories in the system.
#[derive(Error, Debug)]
pub enum SigilError {
    #[error("Configuration error: {message}")]
    Config { message: String },

    #[error("Database operation failed: {operation} - {source}")]
    Database {
        operation: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("Serialization failed: {context}")]
    Serialization {
        context: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("Authentication error: {message}")]
    Auth { message: String },

    #[error("Insufficient LOA: required {required:?}, got {actual:?}")]
    InsufficientLoa { required: LOA, actual: LOA },

    #[error("IRL evaluation error: {message}")]
    Irl { message: String },

    #[error("Canon operation failed: {operation} - {message}")]
    Canon { operation: String, message: String },

    #[error("Encryption operation failed: {operation}")]
    Encryption { operation: String },

    #[error("Cryptographic operation failed: {message}")]
    Crypto { message: String },

    #[error("Mutex lock failed: {resource}")]
    MutexPoisoned { resource: String },

    #[error("I/O operation failed: {operation}")]
    Io {
        operation: String,
        #[source]
        source: std::io::Error,
    },

    #[error("License validation failed: {reason}")]
    License { reason: String },

    #[error("Audit operation failed: {operation}")]
    Audit { operation: String },

    #[error("Extension error: {extension} - {message}")]
    Extension { extension: String, message: String },

    #[error("Validation error: {field} - {message}")]
    Validation { field: String, message: String },

    #[error("Network operation failed: {operation}")]
    Network {
        operation: String,
        #[source]
        source: reqwest::Error,
    },

    #[error("Internal error: {message}")]
    Internal { message: String },

    #[error("Resource not found: {resource} - {id}")]
    NotFound { resource: String, id: String },

    #[error("Too many requests: {message}")]
    RateLimited { message: String },
}

/// Type alias for Result with SigilError
///
/// As recommended in The Rust Book, this provides a convenient
/// shorthand for Result types throughout the codebase.
pub type SigilResult<T> = Result<T, SigilError>;

impl SigilError {
    /// Create a configuration error
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config {
            message: message.into(),
        }
    }

    /// Create a database error
    pub fn database(
        operation: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Database {
            operation: operation.into(),
            source: Box::new(source),
        }
    }

    /// Create a serialization error
    pub fn serialization(context: impl Into<String>, source: serde_json::Error) -> Self {
        Self::Serialization {
            context: context.into(),
            source,
        }
    }

    /// Create an authentication error
    pub fn auth(message: impl Into<String>) -> Self {
        Self::Auth {
            message: message.into(),
        }
    }

    /// Create an IRL error
    pub fn irl(message: impl Into<String>) -> Self {
        Self::Irl {
            message: message.into(),
        }
    }

    /// Create a canon operation error
    pub fn canon(operation: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Canon {
            operation: operation.into(),
            message: message.into(),
        }
    }

    /// Create an encryption error
    pub fn encryption(operation: impl Into<String>) -> Self {
        Self::Encryption {
            operation: operation.into(),
        }
    }

    /// Create a cryptographic error
    pub fn crypto_error(message: impl Into<String>) -> Self {
        Self::Crypto {
            message: message.into(),
        }
    }

    /// Create an I/O error
    pub fn io(operation: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            operation: operation.into(),
            source,
        }
    }

    /// Create a license validation error
    pub fn license(reason: impl Into<String>) -> Self {
        Self::License {
            reason: reason.into(),
        }
    }

    /// Create an audit error
    pub fn audit(operation: impl Into<String>) -> Self {
        Self::Audit {
            operation: operation.into(),
        }
    }

    /// Create an extension error
    pub fn extension(extension: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Extension {
            extension: extension.into(),
            message: message.into(),
        }
    }

    /// Create a validation error
    pub fn validation(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Validation {
            field: field.into(),
            message: message.into(),
        }
    }

    /// Create a network error
    pub fn network(operation: impl Into<String>, source: reqwest::Error) -> Self {
        Self::Network {
            operation: operation.into(),
            source,
        }
    }

    /// Create an internal error
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }

    /// Create an insufficient LOA error
    pub fn insufficient_loa(required: LOA, actual: LOA) -> Self {
        Self::InsufficientLoa { required, actual }
    }

    /// Create a not found error
    pub fn not_found(resource: impl Into<String>, id: impl Into<String>) -> Self {
        Self::NotFound {
            resource: resource.into(),
            id: id.into(),
        }
    }

    /// Create an invalid input error
    pub fn invalid_input(operation: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Validation {
            field: operation.into(),
            message: message.into(),
        }
    }
}

impl IntoResponse for SigilError {
    fn into_response(self) -> Response {
        let status = match self {
            SigilError::Config { .. }
            | SigilError::Serialization { .. }
            | SigilError::Validation { .. }
            | SigilError::Crypto { .. } => StatusCode::BAD_REQUEST,
            SigilError::Auth { .. } => StatusCode::UNAUTHORIZED,
            SigilError::InsufficientLoa { .. } | SigilError::License { .. } => {
                StatusCode::FORBIDDEN
            }
            SigilError::NotFound { .. } => StatusCode::NOT_FOUND,
            SigilError::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            SigilError::Network { .. } => StatusCode::BAD_GATEWAY,
            // Default to 500 for server-side failures
            SigilError::Database { .. }
            | SigilError::MutexPoisoned { .. }
            | SigilError::Io { .. }
            | SigilError::Canon { .. }
            | SigilError::Encryption { .. }
            | SigilError::Audit { .. }
            | SigilError::Extension { .. }
            | SigilError::Internal { .. }
            | SigilError::Irl { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        };

        (status, self.to_string()).into_response()
    }
}

/// Helper trait for safe mutex operations
///
/// Following The Rust Book's patterns for extending existing types,
/// this trait provides safer mutex operations that return proper errors
/// instead of panicking.
pub trait SafeLock<T: ?Sized> {
    /// Safely lock a mutex, returning a SigilError on poison
    fn safe_lock(&self) -> SigilResult<std::sync::MutexGuard<'_, T>>;
}

impl<T: ?Sized> SafeLock<T> for std::sync::Mutex<T> {
    fn safe_lock(&self) -> SigilResult<std::sync::MutexGuard<'_, T>> {
        self.lock().map_err(|_| SigilError::MutexPoisoned {
            resource: "generic_mutex".to_string(),
        })
    }
}

/// Helper trait for safe RwLock read operations
pub trait SafeReadLock<T: ?Sized> {
    /// Safely acquire a read lock
    fn safe_read(&self) -> SigilResult<std::sync::RwLockReadGuard<'_, T>>;
}

impl<T: ?Sized> SafeReadLock<T> for std::sync::RwLock<T> {
    fn safe_read(&self) -> SigilResult<std::sync::RwLockReadGuard<'_, T>> {
        self.read().map_err(|_| SigilError::MutexPoisoned {
            resource: "rwlock_read".to_string(),
        })
    }
}

/// Helper trait for safe RwLock write operations
pub trait SafeWriteLock<T: ?Sized> {
    /// Safely acquire a write lock
    fn safe_write(&self) -> SigilResult<std::sync::RwLockWriteGuard<'_, T>>;
}

impl<T: ?Sized> SafeWriteLock<T> for std::sync::RwLock<T> {
    fn safe_write(&self) -> SigilResult<std::sync::RwLockWriteGuard<'_, T>> {
        self.write().map_err(|_| SigilError::MutexPoisoned {
            resource: "rwlock_write".to_string(),
        })
    }
}

/// Convert from sled errors
impl From<sled::Error> for SigilError {
    fn from(err: sled::Error) -> Self {
        SigilError::database("sled_operation", err)
    }
}

/// Convert from serde_json errors
impl From<serde_json::Error> for SigilError {
    fn from(err: serde_json::Error) -> Self {
        SigilError::serialization("json_operation", err)
    }
}

/// Convert from std::io errors
impl From<std::io::Error> for SigilError {
    fn from(err: std::io::Error) -> Self {
        SigilError::io("io_operation", err)
    }
}

/// Convert from reqwest errors
impl From<reqwest::Error> for SigilError {
    fn from(err: reqwest::Error) -> Self {
        SigilError::network("http_request", err)
    }
}

/// Convert from String errors
impl From<String> for SigilError {
    fn from(err: String) -> Self {
        SigilError::Internal { message: err }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let config_err = SigilError::config("Missing configuration file");
        assert!(config_err.to_string().contains("Configuration error"));

        let loa_err = SigilError::InsufficientLoa {
            required: LOA::Root,
            actual: LOA::Guest,
        };
        assert!(loa_err.to_string().contains("Insufficient LOA"));
    }

    #[test]
    fn test_error_chaining() {
        use std::error::Error;

        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "File not found");
        let sigil_err = SigilError::io("reading config", io_err);

        assert!(sigil_err.source().is_some());
        assert!(sigil_err.to_string().contains("I/O operation failed"));
    }
}
