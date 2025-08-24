//! Rate limiting implementation for DoS protection
//! 
//! This module implements rate limiting to prevent DoS attacks
//! as specified in Phase 2.1 of the security audit plan.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use crate::errors::SigilError;

/// Rate limiter for preventing DoS attacks
pub struct RateLimiter {
    requests: RwLock<HashMap<String, Vec<Instant>>>,
    max_requests: usize,
    window_duration: Duration,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(max_requests: usize, window_seconds: u64) -> Self {
        Self {
            requests: RwLock::new(HashMap::new()),
            max_requests,
            window_duration: Duration::from_secs(window_seconds),
        }
    }
    
    /// Check if a client is within rate limits
    pub async fn check_rate_limit(&self, client_id: &str) -> Result<bool, SigilError> {
        let mut requests = self.requests.write().await;
        let now = Instant::now();
        
        let client_requests = requests.entry(client_id.to_string()).or_insert_with(Vec::new);
        
        // Remove old requests outside the window
        client_requests.retain(|&time| now.duration_since(time) < self.window_duration);
        
        if client_requests.len() >= self.max_requests {
            return Ok(false);
        }
        
        client_requests.push(now);
        Ok(true)
    }
    
    /// Get current request count for a client
    pub async fn get_request_count(&self, client_id: &str) -> usize {
        let requests = self.requests.read().await;
        let now = Instant::now();
        
        if let Some(client_requests) = requests.get(client_id) {
            client_requests.iter()
                .filter(|&time| now.duration_since(*time) < self.window_duration)
                .count()
        } else {
            0
        }
    }
    
    /// Clean up expired entries to prevent memory leaks
    pub async fn cleanup_expired(&self) {
        let mut requests = self.requests.write().await;
        let now = Instant::now();
        
        for (_, client_requests) in requests.iter_mut() {
            client_requests.retain(|&time| now.duration_since(time) < self.window_duration);
        }
        
        // Remove empty entries
        requests.retain(|_, client_requests| !client_requests.is_empty());
    }
    
    /// Get rate limiter statistics
    pub async fn get_stats(&self) -> RateLimiterStats {
        let requests = self.requests.read().await;
        let now = Instant::now();
        
        let mut total_clients = 0;
        let mut total_requests = 0;
        let mut active_clients = 0;
        
        for (_, client_requests) in requests.iter() {
            let active_requests = client_requests.iter()
                .filter(|&time| now.duration_since(*time) < self.window_duration)
                .count();
            
            if active_requests > 0 {
                active_clients += 1;
                total_requests += active_requests;
            }
            total_clients += 1;
        }
        
        RateLimiterStats {
            total_clients,
            active_clients,
            total_requests,
            max_requests: self.max_requests,
            window_duration: self.window_duration,
        }
    }
}

/// Statistics for the rate limiter
#[derive(Debug, Clone)]
pub struct RateLimiterStats {
    pub total_clients: usize,
    pub active_clients: usize,
    pub total_requests: usize,
    pub max_requests: usize,
    pub window_duration: Duration,
}

/// Extract client ID from request (placeholder implementation)
pub fn extract_client_id(req: &TrustCheckRequest) -> String {
    // In a real implementation, this would extract from:
    // - API key
    // - IP address
    // - Session token
    // - User ID
    
    // For now, use a simple hash of the session ID
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    req.session_id.hash(&mut hasher);
    format!("client_{:x}", hasher.finish())
}

// Placeholder for TrustCheckRequest - this should be imported from the actual module
#[derive(Hash)]
pub struct TrustCheckRequest {
    pub session_id: String,
    // Add other fields as needed
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;
    
    #[tokio::test]
    async fn test_rate_limiter_basic() {
        let limiter = RateLimiter::new(3, 1); // 3 requests per second
        
        // First 3 requests should succeed
        assert!(limiter.check_rate_limit("client1").await.unwrap());
        assert!(limiter.check_rate_limit("client1").await.unwrap());
        assert!(limiter.check_rate_limit("client1").await.unwrap());
        
        // 4th request should fail
        assert!(!limiter.check_rate_limit("client1").await.unwrap());
        
        // Wait for window to expire
        sleep(Duration::from_millis(1100)).await;
        
        // Should succeed again
        assert!(limiter.check_rate_limit("client1").await.unwrap());
    }
    
    #[tokio::test]
    async fn test_rate_limiter_multiple_clients() {
        let limiter = RateLimiter::new(2, 1); // 2 requests per second
        
        // Client 1 should be limited
        assert!(limiter.check_rate_limit("client1").await.unwrap());
        assert!(limiter.check_rate_limit("client1").await.unwrap());
        assert!(!limiter.check_rate_limit("client1").await.unwrap());
        
        // Client 2 should still work
        assert!(limiter.check_rate_limit("client2").await.unwrap());
        assert!(limiter.check_rate_limit("client2").await.unwrap());
        assert!(!limiter.check_rate_limit("client2").await.unwrap());
    }
    
    #[tokio::test]
    async fn test_rate_limiter_cleanup() {
        let limiter = RateLimiter::new(1, 1); // 1 request per second
        
        // Make a request
        assert!(limiter.check_rate_limit("client1").await.unwrap());
        
        // Wait for expiration
        sleep(Duration::from_millis(1100)).await;
        
        // Cleanup should remove expired entries
        limiter.cleanup_expired().await;
        
        // Stats should show no active clients
        let stats = limiter.get_stats().await;
        assert_eq!(stats.active_clients, 0);
    }
}
