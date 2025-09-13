use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use crate::loa::LOA;

#[derive(Clone)]
pub struct CurrentUser {
    pub user_id: String,
    pub loa: LOA,
    pub session_id: String,
}

// Middleware should populate CurrentUser from session/cookie/license.
// For now, a dummy extractor that denies if not set.
#[async_trait::async_trait]
impl<S> FromRequestParts<S> for CurrentUser 
where 
    S: Send + Sync 
{
    type Rejection = crate::api_errors::AppError;
    
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // example only: read headers X-User-Id, X-LOA, and X-Session-Id
        let uid = parts.headers.get("x-user-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let session_id = parts.headers.get("x-session-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("default")
            .to_string();
        let loa_str = parts.headers.get("x-loa")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("guest");
            
        if uid.is_empty() { 
            return Err(crate::api_errors::AppError::unauthorized("missing user")); 
        }
        
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
}
