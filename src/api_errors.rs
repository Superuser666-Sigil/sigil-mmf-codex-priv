use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Internal(String),
}

impl AppError {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::BadRequest(msg.into())
    }

    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self::Unauthorized(msg.into())
    }

    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::Forbidden(msg.into())
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::NotFound(msg.into())
    }

    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::Conflict(msg.into())
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}

#[derive(Serialize)]
struct ErrBody {
    error: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (code, msg) = match &self {
            AppError::BadRequest(s) => (StatusCode::BAD_REQUEST, s),
            AppError::Unauthorized(s) => (StatusCode::UNAUTHORIZED, s),
            AppError::Forbidden(s) => (StatusCode::FORBIDDEN, s),
            AppError::NotFound(s) => (StatusCode::NOT_FOUND, s),
            AppError::Conflict(s) => (StatusCode::CONFLICT, s),
            AppError::Internal(s) => (StatusCode::INTERNAL_SERVER_ERROR, s),
        };
        (code, Json(ErrBody { error: msg.clone() })).into_response()
    }
}

// Conversion from String to AppError
impl From<String> for AppError {
    fn from(s: String) -> Self {
        AppError::Internal(s)
    }
}

// Conversion from existing SigilError to AppError
impl From<crate::errors::SigilError> for AppError {
    fn from(err: crate::errors::SigilError) -> Self {
        match err {
            crate::errors::SigilError::Config { message } => AppError::BadRequest(message),
            crate::errors::SigilError::Database { operation, source } => {
                AppError::Internal(format!("Database {operation} failed: {source}"))
            }
            crate::errors::SigilError::Serialization { context, source } => {
                AppError::BadRequest(format!("Serialization {context} failed: {source}"))
            }
            crate::errors::SigilError::Auth { message } => AppError::Unauthorized(message),
            crate::errors::SigilError::InsufficientLoa { required, actual } => AppError::Forbidden(
                format!("Insufficient LOA: required {required:?}, got {actual:?}"),
            ),
            crate::errors::SigilError::Irl { message } => AppError::Internal(message),
            crate::errors::SigilError::Canon { operation, message } => {
                AppError::Internal(format!("Canon {operation} failed: {message}"))
            }
            crate::errors::SigilError::Encryption { operation } => {
                AppError::Internal(format!("Encryption {operation} failed"))
            }
            crate::errors::SigilError::Crypto { message } => {
                AppError::Internal(format!("Cryptographic operation failed: {message}"))
            }
            crate::errors::SigilError::MutexPoisoned { resource } => {
                AppError::Internal(format!("Mutex for {resource} poisoned"))
            }
            crate::errors::SigilError::Io { operation, source } => {
                AppError::Internal(format!("I/O {operation} failed: {source}"))
            }
            crate::errors::SigilError::License { reason } => AppError::Forbidden(reason),
            crate::errors::SigilError::Audit { operation } => {
                AppError::Internal(format!("Audit {operation} failed"))
            }
            crate::errors::SigilError::Extension { extension, message } => {
                AppError::Internal(format!("Extension {extension} error: {message}"))
            }
            crate::errors::SigilError::Validation { field, message } => {
                AppError::BadRequest(format!("Validation error for {field}: {message}"))
            }
            crate::errors::SigilError::Network { operation, source } => {
                AppError::Internal(format!("Network {operation} failed: {source}"))
            }
            crate::errors::SigilError::Internal { message } => AppError::Internal(message),
            crate::errors::SigilError::NotFound { resource, id } => {
                AppError::NotFound(format!("Resource '{resource}' with ID '{id}' not found"))
            }
            crate::errors::SigilError::RateLimited { message } => AppError::Conflict(message),
        }
    }
}
