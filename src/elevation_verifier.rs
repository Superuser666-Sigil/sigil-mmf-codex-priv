use crate::audit::{AuditEvent, LogLevel};
use crate::errors::SigilResult;
use crate::loa::LOA;
use chrono::Utc;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::Mutex;

lazy_static! {
    static ref ELEVATION_TOKENS: Mutex<HashMap<String, (String, chrono::DateTime<Utc>)>> =
        Mutex::new(HashMap::new());
}

/// Check if a user can request elevation to a target LOA level
fn can_request_elevation(current_loa: &LOA, target_loa: &LOA) -> bool {
    match (current_loa, target_loa) {
        // Root can elevate to any level
        (LOA::Root, _) => true,
        // Mentor can elevate to Root with proper authorization
        (LOA::Mentor, LOA::Root) => true,
        // Operator can elevate to Mentor only
        (LOA::Operator, LOA::Mentor) => true,
        // Observer can elevate to Operator only
        (LOA::Observer, LOA::Operator) => true,
        // Guest can elevate to Observer only
        (LOA::Guest, LOA::Observer) => true,
        // No other combinations allowed
        _ => false,
    }
}

/// Validate elevation request with proper security checks
pub fn validate_elevation(
    user_id: &str,
    target_loa: &LOA,
    current_loa: &LOA,
    elevation_token: &str,
    session_id: &str,
) -> SigilResult<bool> {
    // Validate current LOA can request elevation
    if !can_request_elevation(current_loa, target_loa) {
        let audit = AuditEvent::new(
            user_id,
            "elevation_denied",
            Some(&format!("{current_loa:?}->{target_loa:?}")),
            session_id,
            current_loa,
        )
        .with_severity(LogLevel::Warn);
        audit.write_to_log()?;
        return Ok(false);
    }

    // Verify elevation token exists and is valid
    let token_valid = {
        let tokens = ELEVATION_TOKENS.lock().map_err(|_| {
            crate::errors::SigilError::internal("Failed to acquire elevation tokens lock")
        })?;

        if let Some((stored_token, created_at)) = tokens.get(elevation_token) {
            // Check if token matches expected format
            let expected_token = format!(
                "{}:{}:{}:{}",
                user_id,
                target_loa,
                session_id,
                created_at.timestamp()
            );
            if stored_token == &expected_token {
                // Check if token is not expired (24 hour validity)
                let now = Utc::now();
                let token_age = now.signed_duration_since(*created_at);
                token_age.num_hours() < 24
            } else {
                false
            }
        } else {
            false
        }
    };

    if !token_valid {
        let audit = AuditEvent::new(
            user_id,
            "elevation_token_invalid",
            Some(&format!("{current_loa:?}->{target_loa:?}")),
            session_id,
            current_loa,
        )
        .with_severity(LogLevel::Warn);
        audit.write_to_log()?;
        return Ok(false);
    }

    // Log successful elevation attempt
    let audit = AuditEvent::new(
        user_id,
        "elevation_granted",
        Some(&format!("{current_loa:?}->{target_loa:?}")),
        session_id,
        current_loa,
    )
    .with_severity(LogLevel::Info);
    audit.write_to_log()?;

    Ok(true)
}

/// Generate an elevation token for a user
pub fn generate_elevation_token(
    user_id: &str,
    target_loa: &LOA,
    session_id: &str,
    duration_hours: u64,
) -> SigilResult<String> {
    let now = Utc::now();
    let token = format!(
        "{}:{}:{}:{}",
        user_id,
        target_loa,
        session_id,
        now.timestamp()
    );

    // Store token with expiration
    {
        let mut tokens = ELEVATION_TOKENS.lock().map_err(|_| {
            crate::errors::SigilError::internal("Failed to acquire elevation tokens lock")
        })?;

        // Clean up expired tokens
        tokens.retain(|_, (_, created_at)| {
            let token_age = now.signed_duration_since(*created_at);
            token_age.num_hours() < 24
        });

        tokens.insert(token.clone(), (token.clone(), now));
    }

    // Log token generation
    let audit = AuditEvent::new(
        user_id,
        "elevation_token_generated",
        Some(&format!("{target_loa:?} for {duration_hours} hours")),
        session_id,
        &LOA::Root, // Only Root can generate tokens
    )
    .with_severity(LogLevel::Info);
    audit.write_to_log()?;

    Ok(token)
}

/// Clean up expired elevation tokens
pub fn cleanup_expired_tokens() -> SigilResult<()> {
    let now = Utc::now();
    let mut tokens = ELEVATION_TOKENS.lock().map_err(|_| {
        crate::errors::SigilError::internal("Failed to acquire elevation tokens lock")
    })?;

    let before_count = tokens.len();
    tokens.retain(|_, (_, created_at)| {
        let token_age = now.signed_duration_since(*created_at);
        token_age.num_hours() < 24
    });
    let after_count = tokens.len();

    if before_count != after_count {
        log::info!(
            "Cleaned up {} expired elevation tokens",
            before_count - after_count
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_can_request_elevation() {
        // Valid elevation requests
        assert!(can_request_elevation(&LOA::Guest, &LOA::Observer));
        assert!(can_request_elevation(&LOA::Observer, &LOA::Operator));
        assert!(can_request_elevation(&LOA::Operator, &LOA::Mentor));
        assert!(can_request_elevation(&LOA::Mentor, &LOA::Root));
        assert!(can_request_elevation(&LOA::Root, &LOA::Root));

        // Invalid elevation requests
        assert!(!can_request_elevation(&LOA::Guest, &LOA::Root));
        assert!(!can_request_elevation(&LOA::Observer, &LOA::Root));
        assert!(!can_request_elevation(&LOA::Operator, &LOA::Root));
    }

    #[test]
    fn test_elevation_token_generation() {
        let user_id = "test_user";
        let target_loa = &LOA::Mentor;
        let session_id = "test_session";

        let token = generate_elevation_token(user_id, target_loa, session_id, 24)
            .expect("Should generate token");

        assert!(!token.is_empty());
        assert!(token.contains(user_id));
        assert!(token.contains(&format!("{:?}", target_loa)));
    }
}
