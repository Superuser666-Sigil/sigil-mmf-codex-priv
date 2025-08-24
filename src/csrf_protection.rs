//! CSRF protection implementation
//! 
//! This module implements CSRF protection to prevent cross-site request forgery
//! as specified in Phase 2.2 of the security audit plan.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use uuid::Uuid;

/// CSRF protection for preventing cross-site request forgery
pub struct CSRFProtection {
    tokens: RwLock<HashMap<String, (String, Instant)>>,
    token_lifetime: Duration,
}

impl CSRFProtection {
    /// Create a new CSRF protection instance
    pub fn new(token_lifetime_seconds: u64) -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            token_lifetime: Duration::from_secs(token_lifetime_seconds),
        }
    }
    
    /// Generate a new CSRF token for a session
    pub async fn generate_token(&self, session_id: &str) -> String {
        let token = Uuid::new_v4().to_string();
        let mut tokens = self.tokens.write().await;
        tokens.insert(session_id.to_string(), (token.clone(), Instant::now()));
        token
    }
    
    /// Validate a CSRF token for a session
    pub async fn validate_token(&self, session_id: &str, token: &str) -> bool {
        let tokens = self.tokens.write().await;
        let now = Instant::now();
        
        if let Some((stored_token, created)) = tokens.get(session_id) {
            if stored_token == token && now.duration_since(*created) < self.token_lifetime {
                return true;
            }
        }
        
        false
    }
    
    /// Invalidate a CSRF token (use after successful validation)
    pub async fn invalidate_token(&self, session_id: &str) {
        let mut tokens = self.tokens.write().await;
        tokens.remove(session_id);
    }
    
    /// Clean up expired tokens to prevent memory leaks
    pub async fn cleanup_expired(&self) {
        let mut tokens = self.tokens.write().await;
        let now = Instant::now();
        tokens.retain(|_, (_, created)| now.duration_since(*created) < self.token_lifetime);
    }
    
    /// Get CSRF protection statistics
    pub async fn get_stats(&self) -> CSRFStats {
        let tokens = self.tokens.read().await;
        let now = Instant::now();
        
        let mut total_tokens = 0;
        let mut active_tokens = 0;
        let mut expired_tokens = 0;
        
        for (_, (_, created)) in tokens.iter() {
            total_tokens += 1;
            if now.duration_since(*created) < self.token_lifetime {
                active_tokens += 1;
            } else {
                expired_tokens += 1;
            }
        }
        
        CSRFStats {
            total_tokens,
            active_tokens,
            expired_tokens,
            token_lifetime: self.token_lifetime,
        }
    }
    
    /// Check if a session has a valid token
    pub async fn has_valid_token(&self, session_id: &str) -> bool {
        let tokens = self.tokens.read().await;
        let now = Instant::now();
        
        if let Some((_, created)) = tokens.get(session_id) {
            now.duration_since(*created) < self.token_lifetime
        } else {
            false
        }
    }
}

/// Statistics for CSRF protection
#[derive(Debug, Clone)]
pub struct CSRFStats {
    pub total_tokens: usize,
    pub active_tokens: usize,
    pub expired_tokens: usize,
    pub token_lifetime: Duration,
}

/// CSRF token validation result
#[derive(Debug, Clone)]
pub enum CSRFValidationResult {
    Valid,
    Invalid,
    Expired,
    Missing,
}

impl CSRFProtection {
    /// Validate token with detailed result
    pub async fn validate_token_detailed(&self, session_id: &str, token: &str) -> CSRFValidationResult {
        let tokens = self.tokens.read().await;
        let now = Instant::now();
        
        if let Some((stored_token, created)) = tokens.get(session_id) {
            if stored_token == token {
                if now.duration_since(*created) < self.token_lifetime {
                    CSRFValidationResult::Valid
                } else {
                    CSRFValidationResult::Expired
                }
            } else {
                CSRFValidationResult::Invalid
            }
        } else {
            CSRFValidationResult::Missing
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;
    
    #[tokio::test]
    async fn test_csrf_token_generation() {
        let csrf = CSRFProtection::new(60); // 60 second lifetime
        
        let session_id = "test_session_123";
        let token = csrf.generate_token(session_id).await;
        
        // Token should be valid immediately
        assert!(csrf.validate_token(session_id, &token).await);
        
        // Different token should be invalid
        assert!(!csrf.validate_token(session_id, "different_token").await);
    }
    
    #[tokio::test]
    async fn test_csrf_token_expiration() {
        let csrf = CSRFProtection::new(1); // 1 second lifetime
        
        let session_id = "test_session_456";
        let token = csrf.generate_token(session_id).await;
        
        // Token should be valid immediately
        assert!(csrf.validate_token(session_id, &token).await);
        
        // Wait for expiration
        sleep(Duration::from_millis(1100)).await;
        
        // Token should be expired
        assert!(!csrf.validate_token(session_id, &token).await);
    }
    
    #[tokio::test]
    async fn test_csrf_token_invalidation() {
        let csrf = CSRFProtection::new(60);
        
        let session_id = "test_session_789";
        let token = csrf.generate_token(session_id).await;
        
        // Token should be valid
        assert!(csrf.validate_token(session_id, &token).await);
        
        // Invalidate token
        csrf.invalidate_token(session_id).await;
        
        // Token should be invalid
        assert!(!csrf.validate_token(session_id, &token).await);
    }
    
    #[tokio::test]
    async fn test_csrf_cleanup() {
        let csrf = CSRFProtection::new(1); // 1 second lifetime
        
        let session_id = "test_session_cleanup";
        let _token = csrf.generate_token(session_id).await;
        
        // Wait for expiration
        sleep(Duration::from_millis(1100)).await;
        
        // Cleanup should remove expired tokens
        csrf.cleanup_expired().await;
        
        // Stats should show no active tokens
        let stats = csrf.get_stats().await;
        assert_eq!(stats.active_tokens, 0);
        assert_eq!(stats.expired_tokens, 0); // Cleaned up
    }
    
    #[tokio::test]
    async fn test_csrf_detailed_validation() {
        let csrf = CSRFProtection::new(1);
        
        let session_id = "test_session_detailed";
        let token = csrf.generate_token(session_id).await;
        
        // Valid token
        assert!(matches!(
            csrf.validate_token_detailed(session_id, &token).await,
            CSRFValidationResult::Valid
        ));
        
        // Invalid token
        assert!(matches!(
            csrf.validate_token_detailed(session_id, "wrong_token").await,
            CSRFValidationResult::Invalid
        ));
        
        // Missing token
        assert!(matches!(
            csrf.validate_token_detailed("nonexistent_session", &token).await,
            CSRFValidationResult::Missing
        ));
        
        // Wait for expiration
        sleep(Duration::from_millis(1100)).await;
        
        // Expired token
        assert!(matches!(
            csrf.validate_token_detailed(session_id, &token).await,
            CSRFValidationResult::Expired
        ));
    }
}
