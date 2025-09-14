// removed unused axum extractor imports; using header-based helper instead
use crate::loa::LOA;

#[derive(Clone)]
pub struct CurrentUser {
    pub user_id: String,
    pub loa: LOA,
    pub session_id: String,
}

// Simple header-based extractor helper used directly in handlers
pub fn extract_current_user_from_headers(headers: &axum::http::HeaderMap) -> Result<CurrentUser, crate::api_errors::AppError> {
    let uid = headers
        .get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    if uid.is_empty() {
        return Err(crate::api_errors::AppError::unauthorized("missing user"));
    }

    let session_id = headers
        .get("x-session-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("default")
        .to_string();

    let loa_str = headers
        .get("x-loa")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("guest");

    let loa = match loa_str.to_lowercase().as_str() {
        "root" => LOA::Root,
        "mentor" => LOA::Mentor,
        "operator" => LOA::Operator,
        "observer" => LOA::Observer,
        _ => LOA::Guest,
    };

    Ok(CurrentUser {
        user_id: uid,
        loa,
        session_id,
    })
}
