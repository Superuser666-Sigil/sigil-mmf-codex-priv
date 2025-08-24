# Sigil MMF Codex Security Audit Plan
## Addressing Critical and High-Risk Security Issues

**Version:** 1.0  
**Date:** 2024-12-19  
**Auditor:** Security Review Team  
**Scope:** Critical and High-Risk Issues Only  

---

## Executive Summary

This audit plan addresses the most severe security vulnerabilities identified in the Sigil MMF Codex codebase. The current security posture is **3/10** with multiple critical flaws that could lead to complete system compromise. This plan prioritizes fixes based on exploitability, impact, and implementation complexity.

### Risk Assessment
- **Critical Issues:** 5 (Immediate action required)
- **High Risk Issues:** 9 (Action required within 30 days)
- **Total Issues:** 14

---

## Phase 1: Critical Issues (Week 1-2)

### 1.1 Fix Elevation Verification Bypass
**File:** `src/elevation_verifier.rs`  
**Risk:** CRITICAL - Complete privilege escalation bypass  
**Impact:** Root access to any user  

#### Current Issue
```rust
pub fn validate_elevation(_: &str) -> bool {
    true  // ALWAYS ALLOWS ELEVATION!
}
```

#### Remediation Plan
1. **Implement proper elevation checks:**
   ```rust
   use crate::loa::LOA;
   use crate::key_manager::SigilKeyPair;
   use crate::audit::AuditEvent;
   
   pub fn validate_elevation(
       user_id: &str,
       target_loa: &LOA,
       current_loa: &LOA,
       elevation_token: &str,
       session_id: &str,
   ) -> Result<bool, String> {
       // Validate current LOA can request elevation
       if !can_request_elevation(current_loa, target_loa) {
           return Ok(false);
       }
       
       // Verify elevation token cryptographically
       let key_pair = SigilKeyPair::load_from_file("elevation_keys.json")?;
       let token_valid = key_pair.verify(
           format!("{}:{}:{}", user_id, target_loa, session_id).as_bytes(),
           elevation_token,
       )?;
       
       if !token_valid {
           return Ok(false);
       }
       
       // Log elevation attempt
       let audit = AuditEvent::new(
           user_id,
           "elevation_request",
           Some(&format!("{:?}->{:?}", current_loa, target_loa)),
           session_id,
           current_loa,
       ).with_severity(LogLevel::Warn);
       audit.write_to_log()?;
       
       Ok(true)
   }
   ```

2. **Add elevation token generation:**
   ```rust
   pub fn generate_elevation_token(
       user_id: &str,
       target_loa: &LOA,
       session_id: &str,
       duration_seconds: u64,
   ) -> Result<String, String> {
       let key_pair = SigilKeyPair::load_from_file("elevation_keys.json")?;
       let payload = format!("{}:{}:{}:{}", user_id, target_loa, session_id, 
                           chrono::Utc::now().timestamp() + duration_seconds as i64);
       key_pair.sign(payload.as_bytes())
   }
   ```

**Timeline:** 3 days  
**Dependencies:** Key management system  
**Testing:** Unit tests for all elevation paths  

### 1.2 Implement Witness Validation
**File:** `src/sigil_integrity.rs`  
**Risk:** CRITICAL - Trust system bypass  
**Impact:** Unauthorized canon mutations  

#### Current Issue
```rust
pub fn validate_witnesses(...) -> bool {
    if witnesses.len() < 3 {
        return false;
    }
    // Future: verify each witness sig using stored pubkey
    true  // ALWAYS RETURNS TRUE!
}
```

#### Remediation Plan
1. **Implement cryptographic witness validation:**
   ```rust
   use ed25519_dalek::{VerifyingKey, Signature};
   use std::collections::HashMap;
   
   pub struct WitnessRegistry {
       witnesses: HashMap<String, VerifyingKey>,
   }
   
   impl WitnessRegistry {
       pub fn new() -> Self {
           let mut registry = HashMap::new();
           // Load trusted witness public keys
           registry.insert("sigil_init_loader".to_string(), load_witness_key("init_loader.pub"));
           registry.insert("root_mnemonic".to_string(), load_witness_key("root_mnemonic.pub"));
           registry.insert("first_trust_agent".to_string(), load_witness_key("trust_agent.pub"));
           Self { witnesses: registry }
       }
       
       pub fn validate_witnesses(
           &self,
           witnesses: &[WitnessSignature],
           required_loa: &LoaLevel,
           payload: &str,
       ) -> Result<bool, String> {
           if witnesses.len() < 3 {
               return Ok(false);
           }
           
           let mut valid_signatures = 0;
           for witness in witnesses {
               if let Some(public_key) = self.witnesses.get(&witness.witness_id) {
                   let signature = Signature::try_from(
                       base64::engine::general_purpose::STANDARD
                           .decode(&witness.signature)
                           .map_err(|e| format!("Invalid signature encoding: {}", e))?
                   ).map_err(|e| format!("Invalid signature format: {}", e))?;
                   
                   if public_key.verify(payload.as_bytes(), &signature).is_ok() {
                       valid_signatures += 1;
                   }
               }
           }
           
           Ok(valid_signatures >= 3)
       }
   }
   ```

2. **Add witness key management:**
   ```rust
   pub fn load_witness_key(path: &str) -> VerifyingKey {
       let key_bytes = std::fs::read(path)
           .expect(&format!("Failed to load witness key: {}", path));
       VerifyingKey::from_bytes(&key_bytes)
           .expect("Invalid witness key format")
   }
   ```

**Timeline:** 4 days  
**Dependencies:** Ed25519 key management  
**Testing:** Cryptographic validation tests  

### 1.3 Secure Key Storage
**File:** `src/key_manager.rs`  
**Risk:** CRITICAL - Private key exposure  
**Impact:** Complete cryptographic compromise  

#### Current Issue
```rust
pub struct SigilKeyPair {
    pub private_key: String, // Base64 encoded, should be stored securely
}
```

#### Remediation Plan
1. **Implement encrypted key storage:**
   ```rust
   use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
   use rand::RngCore;
   
   pub struct SecureKeyPair {
       pub key_id: String,
       pub public_key: String,
       encrypted_private_key: Vec<u8>,
       key_type: KeyType,
       created_at: chrono::DateTime<chrono::Utc>,
   }
   
   impl SecureKeyPair {
       pub fn generate(key_id: &str, key_type: KeyType, master_key: &[u8; 32]) -> SigilResult<Self> {
           let mut key_bytes = [0u8; 32];
           getrandom::fill(&mut key_bytes)?;
           
           let signing_key = SigningKey::from_bytes(&key_bytes);
           let verifying_key = signing_key.verifying_key();
           
           // Encrypt private key with master key
           let cipher = Aes256Gcm::new_from_slice(master_key)?;
           let nonce = rand::thread_rng().gen::<[u8; 12]>();
           let encrypted_private = cipher.encrypt(&nonce.into(), key_bytes.as_ref())?;
           
           let mut encrypted_data = nonce.to_vec();
           encrypted_data.extend_from_slice(&encrypted_private);
           
           Ok(SecureKeyPair {
               key_id: key_id.to_string(),
               public_key: base64::engine::general_purpose::STANDARD.encode(verifying_key.to_bytes()),
               encrypted_private_key: encrypted_data,
               key_type,
               created_at: chrono::Utc::now(),
           })
       }
       
       pub fn sign(&self, data: &[u8], master_key: &[u8; 32]) -> SigilResult<String> {
           let cipher = Aes256Gcm::new_from_slice(master_key)?;
           let nonce = &self.encrypted_private_key[..12];
           let encrypted_key = &self.encrypted_private_key[12..];
           
           let private_key_bytes = cipher.decrypt(nonce.into(), encrypted_key)?;
           let mut key_array = [0u8; 32];
           key_array.copy_from_slice(&private_key_bytes);
           
           let signing_key = SigningKey::from_bytes(&key_array);
           let signature = signing_key.sign(data);
           
           Ok(base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()))
       }
   }
   ```

2. **Add master key management:**
   ```rust
   pub fn derive_master_key(password: &str, salt: &[u8]) -> [u8; 32] {
       use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
       
       let argon2 = Argon2::default();
       let salt_string = SaltString::encode_b64(salt).unwrap();
       let password_hash = argon2.hash_password(password.as_bytes(), &salt_string).unwrap();
       
       let mut master_key = [0u8; 32];
       master_key.copy_from_slice(&password_hash.hash.unwrap().as_bytes()[..32]);
       master_key
   }
   ```

**Timeline:** 5 days  
**Dependencies:** AES-GCM, Argon2  
**Testing:** Key encryption/decryption tests  

### 1.4 Fix Unsafe Error Handling
**Files:** Multiple files with `expect()` calls  
**Risk:** CRITICAL - Application crashes  
**Impact:** Denial of service, potential data corruption  

#### Current Issues
```rust
// src/canon_store_sled_encrypted.rs:14
let db = sled::open(path).expect("Failed to open sled database");

// src/sigilweb.rs:214
IntCounter::new("trust_check_total", "Total trust check requests").expect("counter")
```

#### Remediation Plan
1. **Replace all `expect()` calls with proper error handling:**
   ```rust
   // Before
   let db = sled::open(path).expect("Failed to open sled database");
   
   // After
   let db = sled::open(path)
       .map_err(|e| SigilError::database("opening sled database", e))?;
   ```

2. **Add comprehensive error handling:**
   ```rust
   // src/sigilweb.rs
   let counter = IntCounter::new("trust_check_total", "Total trust check requests")
       .map_err(|e| {
           error!("Failed to create trust check counter: {}", e);
           SigilError::internal("Failed to initialize metrics")
       })?;
   ```

3. **Implement graceful degradation:**
   ```rust
   pub fn initialize_metrics() -> Result<(), SigilError> {
       match IntCounter::new("trust_check_total", "Total trust check requests") {
           Ok(counter) => {
               TRUST_CHECK_TOTAL.set(counter).map_err(|e| {
                   SigilError::internal("Failed to set trust check counter")
               })?;
               Ok(())
           }
           Err(e) => {
               warn!("Metrics initialization failed: {}", e);
               // Continue without metrics rather than failing
               Ok(())
           }
       }
   }
   ```

**Timeline:** 2 days  
**Dependencies:** Error handling system  
**Testing:** Error path testing  

### 1.5 Implement Input Validation
**Files:** `src/sigilweb.rs`, `src/cli.rs`, `src/extensions.rs`  
**Risk:** CRITICAL - Injection attacks  
**Impact:** Code execution, data corruption  

#### Remediation Plan
1. **Add comprehensive input validation:**
   ```rust
   use regex::Regex;
   use std::collections::HashSet;
   
   pub struct InputValidator {
       allowed_actions: HashSet<String>,
       allowed_targets: HashSet<String>,
       name_pattern: Regex,
   }
   
   impl InputValidator {
       pub fn new() -> Self {
           let mut allowed_actions = HashSet::new();
           allowed_actions.insert("trust_check".to_string());
           allowed_actions.insert("canon_read".to_string());
           allowed_actions.insert("canon_write".to_string());
           
           let mut allowed_targets = HashSet::new();
           allowed_targets.insert("canon".to_string());
           allowed_targets.insert("audit".to_string());
           allowed_targets.insert("config".to_string());
           
           let name_pattern = Regex::new(r"^[a-zA-Z0-9_-]{1,64}$").unwrap();
           
           Self {
               allowed_actions,
               allowed_targets,
               name_pattern,
           }
       }
       
       pub fn validate_trust_request(&self, req: &TrustCheckRequest) -> Result<(), SigilError> {
           // Validate action
           if !self.allowed_actions.contains(&req.action) {
               return Err(SigilError::validation("action", "Invalid action"));
           }
           
           // Validate target if present
           if let Some(target) = &req.target {
               if !self.allowed_targets.contains(target) {
                   return Err(SigilError::validation("target", "Invalid target"));
               }
           }
           
           // Validate session ID
           if !self.name_pattern.is_match(&req.session_id) {
               return Err(SigilError::validation("session_id", "Invalid session ID format"));
           }
           
           // Validate LOA
           LOA::from_str(&req.loa)
               .map_err(|_| SigilError::validation("loa", "Invalid LOA level"))?;
           
           Ok(())
       }
   }
   ```

2. **Add CLI input validation:**
   ```rust
   pub fn validate_cli_input(command: &Commands) -> Result<(), SigilError> {
       match command {
           Commands::GenerateKey { key_id, key_type, .. } => {
               if !is_valid_key_id(key_id) {
                   return Err(SigilError::validation("key_id", "Invalid key ID format"));
               }
               if !is_valid_key_type(key_type) {
                   return Err(SigilError::validation("key_type", "Invalid key type"));
               }
           }
           Commands::Sign { key_id, data, .. } => {
               if !is_valid_key_id(key_id) {
                   return Err(SigilError::validation("key_id", "Invalid key ID format"));
               }
               if data.len() > MAX_SIGN_DATA_SIZE {
                   return Err(SigilError::validation("data", "Data too large"));
               }
           }
           // Add validation for other commands
       }
       Ok(())
   }
   ```

**Timeline:** 3 days  
**Dependencies:** Regex crate  
**Testing:** Input validation tests  

---

## Phase 2: High-Risk Issues (Week 3-6)

### 2.1 Implement Rate Limiting
**File:** `src/sigilweb.rs`  
**Risk:** HIGH - DoS attacks  
**Impact:** Service unavailability  

#### Remediation Plan
```rust
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

pub struct RateLimiter {
    requests: RwLock<HashMap<String, Vec<Instant>>>,
    max_requests: usize,
    window_duration: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window_seconds: u64) -> Self {
        Self {
            requests: RwLock::new(HashMap::new()),
            max_requests,
            window_duration: Duration::from_secs(window_seconds),
        }
    }
    
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
}

// Add to web handlers
async fn check_trust(
    Extension(runtime): Extension<Arc<RwLock<SigilRuntimeCore>>>,
    Extension(rate_limiter): Extension<Arc<RateLimiter>>,
    Json(req): Json<TrustCheckRequest>,
) -> Result<Json<TrustCheckResponse>, (StatusCode, String)> {
    // Check rate limit
    let client_id = extract_client_id(&req); // Implement based on your auth system
    if !rate_limiter.check_rate_limit(&client_id).await.map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Rate limit error: {}", e))
    })? {
        return Err((StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded".to_string()));
    }
    
    // Continue with existing logic...
}
```

**Timeline:** 4 days  
**Dependencies:** Tokio async runtime  
**Testing:** Rate limiting tests  

### 2.2 Add CSRF Protection
**File:** `src/sigilweb.rs`  
**Risk:** HIGH - Cross-site request forgery  
**Impact:** Unauthorized actions  

#### Remediation Plan
```rust
use uuid::Uuid;

pub struct CSRFProtection {
    tokens: RwLock<HashMap<String, (String, Instant)>>,
    token_lifetime: Duration,
}

impl CSRFProtection {
    pub fn new(token_lifetime_seconds: u64) -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            token_lifetime: Duration::from_secs(token_lifetime_seconds),
        }
    }
    
    pub async fn generate_token(&self, session_id: &str) -> String {
        let token = Uuid::new_v4().to_string();
        let mut tokens = self.tokens.write().await;
        tokens.insert(session_id.to_string(), (token.clone(), Instant::now()));
        token
    }
    
    pub async fn validate_token(&self, session_id: &str, token: &str) -> bool {
        let mut tokens = self.tokens.write().await;
        let now = Instant::now();
        
        if let Some((stored_token, created)) = tokens.get(session_id) {
            if stored_token == token && now.duration_since(*created) < self.token_lifetime {
                return true;
            }
        }
        
        false
    }
    
    pub async fn cleanup_expired(&self) {
        let mut tokens = self.tokens.write().await;
        let now = Instant::now();
        tokens.retain(|_, (_, created)| now.duration_since(*created) < self.token_lifetime);
    }
}
```

**Timeline:** 3 days  
**Dependencies:** UUID generation  
**Testing:** CSRF protection tests  

### 2.3 Strengthen LOA Enforcement
**Files:** `src/loa.rs`, `src/canon_guard.rs`  
**Risk:** HIGH - Authorization bypass  
**Impact:** Unauthorized access to sensitive operations  

#### Remediation Plan
1. **Improve LOA enforcement:**
   ```rust
   impl LOA {
       pub fn can_perform_action(&self, action: &str, resource: &str) -> bool {
           match self {
               LOA::Root => true,
               LOA::Mentor => matches!(action, "read" | "write" | "audit" | "validate"),
               LOA::Operator => matches!(action, "read" | "write" | "audit"),
               LOA::Observer => matches!(action, "read" | "audit"),
               LOA::Guest => matches!(action, "read"),
           }
       }
       
       pub fn can_access_resource(&self, resource: &str) -> bool {
           match self {
               LOA::Root => true,
               LOA::Mentor => !resource.contains("system"),
               LOA::Operator => !resource.contains("system") && !resource.contains("admin"),
               LOA::Observer => !resource.contains("system") && !resource.contains("admin") && !resource.contains("write"),
               LOA::Guest => resource.contains("public"),
           }
       }
   }
   ```

2. **Improve verdict extraction:**
   ```rust
   pub fn extract_verdict_from_frozen_chain(chain: &FrozenChain) -> Result<Verdict, String> {
       // Look for explicit verdict in metadata
       if let Some(verdict_str) = chain.metadata.get("verdict") {
           return match verdict_str.as_str() {
               "Allow" => Ok(Verdict::Allow),
               "Deny" => Ok(Verdict::Deny),
               "Defer" => Ok(Verdict::Defer),
               "ManualReview" => Ok(Verdict::ManualReview),
               _ => Err("Invalid verdict in metadata".to_string()),
           };
       }
       
       // Fallback to reasoning analysis with more sophisticated logic
       let reasoning_text = &chain.reasoning_trace.reasoning_steps
           .iter()
           .map(|step| step.logic.clone())
           .collect::<Vec<_>>()
           .join("\n");
       
       // Use more sophisticated analysis
       let verdict_score = analyze_reasoning_for_verdict(reasoning_text);
       
       match verdict_score {
           score if score > 0.8 => Ok(Verdict::Allow),
           score if score < 0.2 => Ok(Verdict::Deny),
           score if score < 0.5 => Ok(Verdict::ManualReview),
           _ => Ok(Verdict::Defer),
       }
   }
   ```

**Timeline:** 5 days  
**Dependencies:** None  
**Testing:** LOA enforcement tests  

### 2.4 Implement Database Security
**Files:** `src/canon_store_sled_encrypted.rs`, `src/canon_store_sled.rs`  
**Risk:** HIGH - Data exposure, unauthorized access  
**Impact:** Sensitive data compromise  

#### Remediation Plan
1. **Mandatory encryption:**
   ```rust
   impl CanonStoreSled {
       pub fn new(path: &str, encryption_key: &[u8; 32]) -> Result<Self, String> {
           let db = sled::open(path)
               .map_err(|e| format!("Failed to open sled database: {}", e))?;
           
           // Verify encryption key is set
           if encryption_key.iter().all(|&b| b == 0) {
               return Err("Encryption key cannot be all zeros".to_string());
           }
           
           Ok(Self { 
               db,
               encryption_key: *encryption_key,
           })
       }
       
       fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, String> {
           let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
               .map_err(|e| format!("Invalid encryption key: {}", e))?;
           
           let nonce = rand::thread_rng().gen::<[u8; 12]>();
           let encrypted = cipher.encrypt(&nonce.into(), data)
               .map_err(|e| format!("Encryption failed: {}", e))?;
           
           let mut result = nonce.to_vec();
           result.extend_from_slice(&encrypted);
           Ok(result)
       }
       
       fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, String> {
           if encrypted_data.len() < 12 {
               return Err("Invalid encrypted data format".to_string());
           }
           
           let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
               .map_err(|e| format!("Invalid encryption key: {}", e))?;
           
           let nonce = &encrypted_data[..12];
           let data = &encrypted_data[12..];
           
           cipher.decrypt(nonce.into(), data)
               .map_err(|e| format!("Decryption failed: {}", e))
       }
   }
   ```

2. **Add access controls:**
   ```rust
   pub struct DatabaseAccessControl {
       allowed_operations: HashMap<String, Vec<String>>,
       audit_log: Arc<Mutex<Vec<DatabaseAuditEvent>>>,
   }
   
   impl DatabaseAccessControl {
       pub fn can_perform_operation(&self, user_id: &str, operation: &str, resource: &str) -> bool {
           if let Some(allowed_ops) = self.allowed_operations.get(user_id) {
               allowed_ops.contains(&operation.to_string())
           } else {
               false
           }
       }
       
       pub fn log_operation(&self, user_id: &str, operation: &str, resource: &str, success: bool) {
           let event = DatabaseAuditEvent {
               timestamp: chrono::Utc::now(),
               user_id: user_id.to_string(),
               operation: operation.to_string(),
               resource: resource.to_string(),
               success,
           };
           
           if let Ok(mut log) = self.audit_log.lock() {
               log.push(event);
           }
       }
   }
   ```

**Timeline:** 6 days  
**Dependencies:** AES-GCM encryption  
**Testing:** Database security tests  

### 2.5 Add Audit Trail Hardening
**Files:** `src/audit_chain.rs`, `src/audit_store.rs`  
**Risk:** HIGH - Audit trail tampering  
**Impact:** Loss of accountability, forensic evidence  

#### Remediation Plan
1. **Cryptographic audit trail:**
   ```rust
   use sha2::{Digest, Sha256};
   use ed25519_dalek::SigningKey;
   
   pub struct SecureAuditChain {
       pub chain_id: String,
       pub content_hash: String,
       pub merkle_root: String,
       pub signature: String,
       pub timestamp: chrono::DateTime<chrono::Utc>,
       pub parent_hashes: Vec<String>,
   }
   
   impl SecureAuditChain {
       pub fn create_chain(
           content: &str,
           parent_chains: &[SecureAuditChain],
           signing_key: &SigningKey,
       ) -> Result<Self, String> {
           let mut hasher = Sha256::new();
           hasher.update(content.as_bytes());
           
           // Include parent hashes in content hash
           for parent in parent_chains {
               hasher.update(&parent.content_hash);
           }
           
           let content_hash = format!("{:x}", hasher.finalize());
           
           // Create Merkle tree from content and parent hashes
           let merkle_root = Self::create_merkle_root(content, parent_chains)?;
           
           // Sign the chain
           let signature_data = format!("{}:{}:{}", content_hash, merkle_root, 
               chrono::Utc::now().timestamp());
           let signature = signing_key.sign(signature_data.as_bytes());
           
           Ok(SecureAuditChain {
               chain_id: Uuid::new_v4().to_string(),
               content_hash,
               merkle_root,
               signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
               timestamp: chrono::Utc::now(),
               parent_hashes: parent_chains.iter().map(|c| c.content_hash.clone()).collect(),
           })
       }
       
       pub fn verify_integrity(&self, verifying_key: &VerifyingKey) -> Result<bool, String> {
           // Verify signature
           let signature_data = format!("{}:{}:{}", self.content_hash, self.merkle_root, 
               self.timestamp.timestamp());
           let signature = Signature::try_from(
               base64::engine::general_purpose::STANDARD.decode(&self.signature)?
           )?;
           
           verifying_key.verify(signature_data.as_bytes(), &signature)
               .map(|_| true)
               .map_err(|e| format!("Signature verification failed: {}", e))
       }
   }
   ```

2. **Immutable audit storage:**
   ```rust
   pub struct ImmutableAuditStore {
       storage_path: String,
       signing_key: SigningKey,
       verifying_key: VerifyingKey,
   }
   
   impl ImmutableAuditStore {
       pub fn write_chain(&self, chain: &SecureAuditChain) -> Result<(), String> {
           // Verify chain integrity before writing
           if !chain.verify_integrity(&self.verifying_key)? {
               return Err("Chain integrity verification failed".to_string());
           }
           
           // Append to immutable log
           let file = OpenOptions::new()
               .create(true)
               .append(true)
               .open(&self.storage_path)
               .map_err(|e| format!("Failed to open audit log: {}", e))?;
           
           let json = serde_json::to_string(chain)
               .map_err(|e| format!("Failed to serialize chain: {}", e))?;
           
           writeln!(file, "{}", json)
               .map_err(|e| format!("Failed to write chain: {}", e))?;
           
           Ok(())
       }
   }
   ```

**Timeline:** 5 days  
**Dependencies:** Ed25519 signatures, SHA256  
**Testing:** Audit integrity tests  

### 2.6 Implement Configuration Security
**Files:** `src/config_loader.rs`, `src/config.rs`  
**Risk:** HIGH - Configuration exposure  
**Impact:** Sensitive data exposure  

#### Remediation Plan
1. **Encrypted configuration:**
   ```rust
   use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
   
   pub struct SecureConfig {
       encrypted_data: Vec<u8>,
       config_hash: String,
   }
   
   impl SecureConfig {
       pub fn load_encrypted(path: &str, master_key: &[u8; 32]) -> Result<MMFConfig, String> {
           let encrypted_data = std::fs::read(path)
               .map_err(|e| format!("Failed to read config: {}", e))?;
           
           let cipher = Aes256Gcm::new_from_slice(master_key)
               .map_err(|e| format!("Invalid master key: {}", e))?;
           
           let nonce = &encrypted_data[..12];
           let data = &encrypted_data[12..];
           
           let decrypted = cipher.decrypt(nonce.into(), data)
               .map_err(|e| format!("Failed to decrypt config: {}", e))?;
           
           let config: MMFConfig = serde_json::from_slice(&decrypted)
               .map_err(|e| format!("Failed to parse config: {}", e))?;
           
           Ok(config)
       }
       
       pub fn save_encrypted(config: &MMFConfig, path: &str, master_key: &[u8; 32]) -> Result<(), String> {
           let json_data = serde_json::to_vec(config)
               .map_err(|e| format!("Failed to serialize config: {}", e))?;
           
           let cipher = Aes256Gcm::new_from_slice(master_key)
               .map_err(|e| format!("Invalid master key: {}", e))?;
           
           let nonce = rand::thread_rng().gen::<[u8; 12]>();
           let encrypted = cipher.encrypt(&nonce.into(), json_data.as_ref())
               .map_err(|e| format!("Failed to encrypt config: {}", e))?;
           
           let mut result = nonce.to_vec();
           result.extend_from_slice(&encrypted);
           
           std::fs::write(path, result)
               .map_err(|e| format!("Failed to write config: {}", e))?;
           
           Ok(())
       }
   }
   ```

2. **Environment variable validation:**
   ```rust
   pub fn validate_environment() -> Result<(), Vec<String>> {
       let mut errors = Vec::new();
       
       // Validate required environment variables
       let required_vars = [
           "MMF_DATA_DIR",
           "MMF_AUDIT_LOG",
           "SIGIL_AES_KEY",
       ];
       
       for var in &required_vars {
           if std::env::var(var).is_err() {
               errors.push(format!("Missing required environment variable: {}", var));
           }
       }
       
       // Validate SIGIL_AES_KEY format
       if let Ok(key) = std::env::var("SIGIL_AES_KEY") {
           if key.len() != 44 { // Base64 encoded 32-byte key
               errors.push("SIGIL_AES_KEY must be a valid base64-encoded 32-byte key".to_string());
           }
           
           if let Err(_) = base64::engine::general_purpose::STANDARD.decode(&key) {
               errors.push("SIGIL_AES_KEY must be valid base64".to_string());
           }
       }
       
       if errors.is_empty() {
           Ok(())
       } else {
           Err(errors)
       }
   }
   ```

**Timeline:** 4 days  
**Dependencies:** AES-GCM encryption  
**Testing:** Configuration security tests  

### 2.7 Add Network Security
**File:** `src/irl_adapter.rs`  
**Risk:** HIGH - Network attacks  
**Impact:** Data interception, unauthorized access  

#### Remediation Plan
```rust
use reqwest::Client;
use std::time::Duration;

pub struct SecureNetworkClient {
    client: Client,
    base_url: String,
    timeout: Duration,
}

impl SecureNetworkClient {
    pub fn new(base_url: String, timeout_seconds: u64) -> Result<Self, String> {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_seconds))
            .use_rustls_tls() // Use rustls instead of OpenSSL
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;
        
        Ok(Self {
            client,
            base_url,
            timeout: Duration::from_secs(timeout_seconds),
        })
    }
    
    pub async fn query_phi4_executor(
        &self,
        context: &str,
        input: &str,
        api_key: &str,
    ) -> Result<IRLResponse, String> {
        let payload = serde_json::json!({
            "context": context,
            "input": input,
            "model": "phi-4",
            "stream": false
        });
        
        let response = self.client
            .post(&format!("{}/irl", self.base_url))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", api_key))
            .header("User-Agent", "Sigil-IRL-Client/1.0")
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Network request failed: {}", e))?;
        
        if !response.status().is_success() {
            return Err(format!("HTTP error: {}", response.status()));
        }
        
        response.json::<IRLResponse>()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    }
}
```

**Timeline:** 3 days  
**Dependencies:** Reqwest with rustls  
**Testing:** Network security tests  

### 2.8 Implement File System Security
**Files:** `src/backup_recovery.rs`, `src/canon_loader.rs`  
**Risk:** HIGH - File system attacks  
**Impact:** Data corruption, unauthorized access  

#### Remediation Plan
```rust
use std::path::Path;
use sha2::{Digest, Sha256};

pub struct SecureFileOperations {
    allowed_paths: Vec<String>,
    max_file_size: usize,
}

impl SecureFileOperations {
    pub fn new(allowed_paths: Vec<String>, max_file_size: usize) -> Self {
        Self {
            allowed_paths,
            max_file_size,
        }
    }
    
    pub fn validate_path(&self, path: &Path) -> Result<(), String> {
        let path_str = path.to_string_lossy();
        
        // Check if path is within allowed directories
        let is_allowed = self.allowed_paths.iter().any(|allowed| {
            path_str.starts_with(allowed)
        });
        
        if !is_allowed {
            return Err(format!("Path {} is not in allowed directories", path_str));
        }
        
        // Check for path traversal attempts
        if path_str.contains("..") || path_str.contains("~") {
            return Err("Path traversal attempt detected".to_string());
        }
        
        Ok(())
    }
    
    pub fn read_file_secure(&self, path: &Path) -> Result<Vec<u8>, String> {
        self.validate_path(path)?;
        
        let metadata = std::fs::metadata(path)
            .map_err(|e| format!("Failed to get file metadata: {}", e))?;
        
        if metadata.len() > self.max_file_size as u64 {
            return Err("File too large".to_string());
        }
        
        std::fs::read(path)
            .map_err(|e| format!("Failed to read file: {}", e))
    }
    
    pub fn calculate_file_hash(&self, path: &Path) -> Result<String, String> {
        let data = self.read_file_secure(path)?;
        let mut hasher = Sha256::new();
        hasher.update(&data);
        Ok(format!("{:x}", hasher.finalize()))
    }
    
    pub fn verify_file_integrity(&self, path: &Path, expected_hash: &str) -> Result<bool, String> {
        let actual_hash = self.calculate_file_hash(path)?;
        Ok(actual_hash == expected_hash)
    }
}
```

**Timeline:** 4 days  
**Dependencies:** SHA256 hashing  
**Testing:** File system security tests  

---

## Implementation Timeline

### Week 1-2: Critical Issues
- **Day 1-3:** Fix elevation verification bypass
- **Day 4-7:** Implement witness validation
- **Day 8-12:** Secure key storage
- **Day 13-14:** Fix unsafe error handling

### Week 3-6: High-Risk Issues
- **Week 3:** Rate limiting, CSRF protection
- **Week 4:** LOA enforcement, database security
- **Week 5:** Audit trail hardening, configuration security
- **Week 6:** Network security, file system security

### Week 7: Testing and Validation
- Comprehensive security testing
- Penetration testing
- Code review
- Documentation updates

---

## Testing Strategy

### Unit Tests
- All security functions must have 100% test coverage
- Include negative test cases (invalid inputs, edge cases)
- Test error conditions and failure modes

### Integration Tests
- End-to-end security flow testing
- Cross-component security testing
- Performance testing under load

### Security Tests
- Penetration testing of all endpoints
- Cryptographic validation testing
- Input fuzzing and injection testing
- Rate limiting effectiveness testing

---

## Success Criteria

### Phase 1 (Critical Issues)
- [ ] No `expect()` calls in production code
- [ ] All elevation requests properly validated
- [ ] All witness signatures cryptographically verified
- [ ] All private keys encrypted at rest
- [ ] All external inputs validated and sanitized

### Phase 2 (High-Risk Issues)
- [ ] Rate limiting active on all endpoints
- [ ] CSRF protection implemented
- [ ] LOA enforcement cannot be bypassed
- [ ] All database operations encrypted
- [ ] Audit trails cryptographically protected
- [ ] Configuration encrypted and validated
- [ ] Network communications secured
- [ ] File operations protected against attacks

### Overall Security Goals
- **Security Score:** Improve from 3/10 to 8/10
- **Zero Critical Vulnerabilities:** All critical issues resolved
- **Comprehensive Logging:** All security events logged
- **Defense in Depth:** Multiple layers of security controls
- **Compliance Ready:** Meets industry security standards

---

## Risk Mitigation

### During Implementation
- **Feature Flags:** Implement security features behind feature flags
- **Rollback Plan:** Maintain ability to rollback changes
- **Monitoring:** Enhanced monitoring during deployment
- **Gradual Rollout:** Deploy security changes incrementally

### Post-Implementation
- **Continuous Monitoring:** Monitor for security incidents
- **Regular Audits:** Quarterly security audits
- **Vulnerability Management:** Regular vulnerability assessments
- **Security Training:** Team security awareness training

---

## Dependencies and Resources

### Required Dependencies
- `aes-gcm = "0.10.3"` - For encryption
- `ed25519-dalek = "2.2.0"` - For digital signatures
- `argon2 = "0.5"` - For key derivation
- `regex = "1.10"` - For input validation
- `rand = "0.9.2"` - For secure random generation

### Team Requirements
- **Security Engineer:** 1 FTE for 6 weeks
- **Rust Developer:** 1 FTE for 6 weeks
- **DevOps Engineer:** 0.5 FTE for 2 weeks
- **QA Engineer:** 0.5 FTE for 2 weeks

### Infrastructure Requirements
- **Development Environment:** Secure development setup
- **Testing Environment:** Isolated testing infrastructure
- **Staging Environment:** Production-like staging environment
- **Monitoring Tools:** Security monitoring and alerting

---

## Conclusion

This audit plan addresses the most critical security vulnerabilities in the Sigil MMF Codex codebase. Implementation should begin immediately with Phase 1 critical issues, followed by Phase 2 high-risk issues. The plan follows Rust security best practices and industry standards for secure software development.

**Priority:** Immediate implementation required  
**Risk Level:** Critical  
**Estimated Effort:** 6 weeks  
**Success Probability:** High (with proper implementation and testing)
