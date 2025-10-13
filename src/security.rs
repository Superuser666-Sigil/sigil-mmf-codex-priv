// removed unused axum extractor imports; using header-based helper instead
use crate::loa::LOA;

#[derive(Clone)]
pub struct CurrentUser {
    pub user_id: String,
    pub loa: LOA,
    pub session_id: String,
}

// Simple header-based extractor helper used directly in handlers (dev only)
pub fn extract_current_user_from_headers(
    headers: &axum::http::HeaderMap,
) -> Result<CurrentUser, crate::api_errors::AppError> {
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

/// License-first extractor with optional dev fallback to headers.
///
/// Behavior:
/// - If header `x-sigil-license` or cookie `sigil_license` present, validate and derive LOA/user.
/// - If not present and `MMF_DEV_HEADER_AUTH=true`, fall back to `extract_current_user_from_headers`.
/// - Otherwise, return 401.
pub fn extract_current_user(
    headers: &axum::http::HeaderMap,
    runtime_id: &str,
    canon_fingerprint: &str,
) -> Result<CurrentUser, crate::api_errors::AppError> {
    // Try header first
    if let Some(lh) = headers.get("x-sigil-license").and_then(|v| v.to_str().ok()) {
        match crate::license_validator::validate_license_content(lh, runtime_id, canon_fingerprint)
        {
            Ok(v) if v.valid => {
                let session_id = headers
                    .get("x-session-id")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("default")
                    .to_string();
                return Ok(CurrentUser {
                    user_id: v.license.owner.hash_id,
                    loa: v.license.loa,
                    session_id,
                });
            }
            Ok(_) => return Err(crate::api_errors::AppError::unauthorized("invalid license")),
            Err(_) => {
                return Err(crate::api_errors::AppError::unauthorized(
                    "malformed license",
                ));
            }
        }
    }

    // Try cookie `sigil_license`
    if let Some(cookie_header) = headers.get("cookie").and_then(|v| v.to_str().ok()) {
        // naive cookie parse: look for sigil_license=...
        if let Some(start) = cookie_header.find("sigil_license=") {
            let after = &cookie_header[start + "sigil_license=".len()..];
            let end = after.find(';').unwrap_or(after.len());
            let value = &after[..end];
            // value may be URL-encoded; try as-is first
            match crate::license_validator::validate_license_content(
                value,
                runtime_id,
                canon_fingerprint,
            ) {
                Ok(v) if v.valid => {
                    let session_id = headers
                        .get("x-session-id")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("default")
                        .to_string();
                    return Ok(CurrentUser {
                        user_id: v.license.owner.hash_id,
                        loa: v.license.loa,
                        session_id,
                    });
                }
                Ok(_) => return Err(crate::api_errors::AppError::unauthorized("invalid license")),
                Err(_) => {
                    return Err(crate::api_errors::AppError::unauthorized(
                        "malformed license",
                    ));
                }
            }
        }
    }

    // Dev fallback controlled by compile-time feature and env var
    // Requires both: feature "dev-auth" and MMF_DEV_HEADER_AUTH=true
    let dev_ok_env = std::env::var("MMF_DEV_HEADER_AUTH")
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(false);
    let dev_ok = cfg!(feature = "dev-auth") && dev_ok_env;
    if dev_ok {
        return extract_current_user_from_headers(headers);
    }

    Err(crate::api_errors::AppError::unauthorized("missing user"))
}
