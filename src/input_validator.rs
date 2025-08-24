use crate::errors::SigilResult;
use crate::loa::LOA;
use regex::Regex;
use std::collections::HashSet;
use std::str::FromStr;
use lazy_static::lazy_static;

lazy_static! {
    static ref NAME_PATTERN: Regex = Regex::new(r"^[a-zA-Z0-9_-]{1,64}$").unwrap();
    static ref SESSION_ID_PATTERN: Regex = Regex::new(r"^[a-zA-Z0-9_-]{1,128}$").unwrap();
    static ref KEY_ID_PATTERN: Regex = Regex::new(r"^[a-zA-Z0-9_-]{1,32}$").unwrap();
    static ref PATH_PATTERN: Regex = Regex::new(r"^[a-zA-Z0-9/._-]+$").unwrap();
}

/// Input validator for comprehensive validation of all external inputs
pub struct InputValidator {
    allowed_actions: HashSet<String>,
    allowed_targets: HashSet<String>,
    allowed_key_types: HashSet<String>,
    max_data_size: usize,
}

impl InputValidator {
    pub fn new() -> Self {
        let mut allowed_actions = HashSet::new();
        allowed_actions.insert("trust_check".to_string());
        allowed_actions.insert("canon_read".to_string());
        allowed_actions.insert("canon_write".to_string());
        allowed_actions.insert("audit_read".to_string());
        allowed_actions.insert("config_read".to_string());
        allowed_actions.insert("config_write".to_string());
        allowed_actions.insert("elevation_request".to_string());
        allowed_actions.insert("extension_register".to_string());
        allowed_actions.insert("extension_unregister".to_string());

        let mut allowed_targets = HashSet::new();
        allowed_targets.insert("canon".to_string());
        allowed_targets.insert("audit".to_string());
        allowed_targets.insert("config".to_string());
        allowed_targets.insert("system".to_string());
        allowed_targets.insert("extensions".to_string());

        let mut allowed_key_types = HashSet::new();
        allowed_key_types.insert("license".to_string());
        allowed_key_types.insert("canon".to_string());
        allowed_key_types.insert("witness".to_string());

        Self {
            allowed_actions,
            allowed_targets,
            allowed_key_types,
            max_data_size: 1024 * 1024, // 1MB
        }
    }

    /// Validate trust check request
    pub fn validate_trust_request(&self, req: &TrustCheckRequest) -> SigilResult<()> {
        // Validate action
        if !self.allowed_actions.contains(&req.action) {
            return Err(crate::errors::SigilError::validation("action", "Invalid action"));
        }
        
        // Validate target if present
        if let Some(target) = &req.target
            && !self.allowed_targets.contains(target) {
            return Err(crate::errors::SigilError::validation("target", "Invalid target"));
        }
        
        // Validate session ID
        if !SESSION_ID_PATTERN.is_match(&req.session_id) {
            return Err(crate::errors::SigilError::validation("session_id", "Invalid session ID format"));
        }
        
        // Validate LOA
        LOA::from_str(&req.loa)
            .map_err(|_| crate::errors::SigilError::validation("loa", "Invalid LOA level"))?;
        
        // Validate who field
        if req.who.is_empty() || req.who.len() > 128 {
            return Err(crate::errors::SigilError::validation("who", "Invalid user identifier"));
        }
        
        // Check for potential injection patterns
        if self.contains_injection_patterns(&req.who) || 
           self.contains_injection_patterns(&req.action) ||
           req.target.as_ref().is_some_and(|t| self.contains_injection_patterns(t)) {
            return Err(crate::errors::SigilError::validation("input", "Potential injection detected"));
        }
        
        Ok(())
    }

    /// Validate CLI input
    pub fn validate_cli_input(&self, command: &CliCommand) -> SigilResult<()> {
        match command {
            CliCommand::GenerateKey { key_id, key_type, .. } => {
                if !KEY_ID_PATTERN.is_match(key_id) {
                    return Err(crate::errors::SigilError::validation("key_id", "Invalid key ID format"));
                }
                if !self.allowed_key_types.contains(key_type) {
                    return Err(crate::errors::SigilError::validation("key_type", "Invalid key type"));
                }
            }
            CliCommand::Sign { key_id, data, .. } => {
                if !KEY_ID_PATTERN.is_match(key_id) {
                    return Err(crate::errors::SigilError::validation("key_id", "Invalid key ID format"));
                }
                if data.len() > self.max_data_size {
                    return Err(crate::errors::SigilError::validation("data", "Data too large"));
                }
                if self.contains_injection_patterns(data) {
                    return Err(crate::errors::SigilError::validation("data", "Potential injection detected"));
                }
            }
            CliCommand::Serve { host, port } => {
                if !self.is_valid_host(host) {
                    return Err(crate::errors::SigilError::validation("host", "Invalid host format"));
                }
                if *port == 0 {
                    return Err(crate::errors::SigilError::validation("port", "Invalid port number"));
                }
            }
            CliCommand::Validate { file } => {
                if !PATH_PATTERN.is_match(file) {
                    return Err(crate::errors::SigilError::validation("file", "Invalid file path"));
                }
                if self.contains_path_traversal(file) {
                    return Err(crate::errors::SigilError::validation("file", "Path traversal attempt detected"));
                }
            }
            CliCommand::RegisterExtension { name, loa } => {
                if !NAME_PATTERN.is_match(name) {
                    return Err(crate::errors::SigilError::validation("name", "Invalid extension name"));
                }
                LOA::from_str(loa)
                    .map_err(|_| crate::errors::SigilError::validation("loa", "Invalid LOA level"))?;
            }
        }
        
        Ok(())
    }

    /// Validate extension registration
    pub fn validate_extension_registration(&self, req: &ExtensionRegisterRequest) -> SigilResult<()> {
        if req.name.trim().is_empty() {
            return Err(crate::errors::SigilError::validation("name", "Extension name cannot be empty"));
        }
        
        if !NAME_PATTERN.is_match(&req.name) {
            return Err(crate::errors::SigilError::validation("name", "Invalid extension name format"));
        }
        
        if req.name.len() > 64 {
            return Err(crate::errors::SigilError::validation("name", "Extension name too long"));
        }
        
        LOA::from_str(&req.loa)
            .map_err(|_| crate::errors::SigilError::validation("loa", "Invalid LOA level"))?;
        
        if self.contains_injection_patterns(&req.name) {
            return Err(crate::errors::SigilError::validation("name", "Potential injection detected"));
        }
        
        Ok(())
    }

    /// Validate file path
    pub fn validate_file_path(&self, path: &str) -> SigilResult<()> {
        if path.is_empty() {
            return Err(crate::errors::SigilError::validation("path", "Path cannot be empty"));
        }
        
        if !PATH_PATTERN.is_match(path) {
            return Err(crate::errors::SigilError::validation("path", "Invalid path format"));
        }
        
        if self.contains_path_traversal(path) {
            return Err(crate::errors::SigilError::validation("path", "Path traversal attempt detected"));
        }
        
        Ok(())
    }

    /// Validate data size
    pub fn validate_data_size(&self, data: &[u8]) -> SigilResult<()> {
        if data.len() > self.max_data_size {
            return Err(crate::errors::SigilError::validation("data", "Data too large"));
        }
        
        Ok(())
    }

    /// Check for injection patterns
    fn contains_injection_patterns(&self, input: &str) -> bool {
        let dangerous_patterns = [
            "script",
            "javascript:",
            "data:",
            "vbscript:",
            "onload",
            "onerror",
            "onclick",
            "eval(",
            "exec(",
            "system(",
            "shell_exec",
            "passthru",
            "include",
            "require",
            "file_get_contents",
            "fopen",
            "fwrite",
            "unlink",
            "rmdir",
            "mkdir",
            "chmod",
            "chown",
            "sudo",
            "su",
            "root",
            "admin",
            "password",
            "passwd",
            "shadow",
            "etc/passwd",
            "/etc/shadow",
            "proc/",
            "/proc/",
            "sys/",
            "/sys/",
            "dev/",
            "/dev/",
            "tmp/",
            "/tmp/",
            "var/",
            "/var/",
            "home/",
            "/home/",
            "root/",
            "/root/",
        ];
        
        let input_lower = input.to_lowercase();
        dangerous_patterns.iter().any(|pattern| input_lower.contains(pattern))
    }

    /// Check for path traversal attempts
    fn contains_path_traversal(&self, path: &str) -> bool {
        let traversal_patterns = [
            "..",
            "~",
            "\\",
            "//",
            "\\\\",
            "..\\",
            "..//",
            "~\\",
            "~//",
        ];
        
        traversal_patterns.iter().any(|pattern| path.contains(pattern))
    }

    /// Validate host format
    fn is_valid_host(&self, host: &str) -> bool {
        if host.is_empty() {
            return false;
        }
        
        // Allow localhost, IP addresses, and valid hostnames
        if host == "localhost" || host == "127.0.0.1" || host == "0.0.0.0" {
            return true;
        }
        
        // Check for valid IP address format
        if host.parse::<std::net::IpAddr>().is_ok() {
            return true;
        }
        
        // Check for valid hostname format
        let hostname_pattern = Regex::new(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$").unwrap();
        hostname_pattern.is_match(host)
    }
}

/// Trust check request structure
#[derive(Debug)]
pub struct TrustCheckRequest {
    pub who: String,
    pub action: String,
    pub target: Option<String>,
    pub session_id: String,
    pub loa: String,
}

/// CLI command structure
#[derive(Debug)]
pub enum CliCommand {
    GenerateKey { key_id: String, key_type: String, output: Option<String> },
    Sign { key_id: String, data: String, output: Option<String> },
    Serve { host: String, port: u16 },
    Validate { file: String },
    RegisterExtension { name: String, loa: String },
}

/// Extension registration request structure
#[derive(Debug)]
pub struct ExtensionRegisterRequest {
    pub name: String,
    pub loa: String,
}

impl Default for InputValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_request_validation() {
        let validator = InputValidator::new();
        
        // Valid request
        let valid_req = TrustCheckRequest {
            who: "test_user".to_string(),
            action: "trust_check".to_string(),
            target: Some("canon".to_string()),
            session_id: "session_123".to_string(),
            loa: "Observer".to_string(),
        };
        
        assert!(validator.validate_trust_request(&valid_req).is_ok());
        
        // Invalid action
        let invalid_req = TrustCheckRequest {
            who: "test_user".to_string(),
            action: "malicious_action".to_string(),
            target: Some("canon".to_string()),
            session_id: "session_123".to_string(),
            loa: "Observer".to_string(),
        };
        
        assert!(validator.validate_trust_request(&invalid_req).is_err());
    }

    #[test]
    fn test_injection_detection() {
        let validator = InputValidator::new();
        
        // Test injection patterns
        assert!(validator.contains_injection_patterns("javascript:alert('xss')"));
        assert!(validator.contains_injection_patterns("eval(malicious_code)"));
        assert!(validator.contains_injection_patterns("system(command)"));
        
        // Test safe inputs
        assert!(!validator.contains_injection_patterns("normal_text"));
        assert!(!validator.contains_injection_patterns("valid_action"));
    }

    #[test]
    fn test_path_traversal_detection() {
        let validator = InputValidator::new();
        
        // Test path traversal attempts
        assert!(validator.contains_path_traversal("../../../etc/passwd"));
        assert!(validator.contains_path_traversal("~/.ssh/id_rsa"));
        assert!(validator.contains_path_traversal("..\\windows\\system32"));
        
        // Test safe paths
        assert!(!validator.contains_path_traversal("valid/path/file.txt"));
        assert!(!validator.contains_path_traversal("data/config.json"));
    }

    #[test]
    fn test_host_validation() {
        let validator = InputValidator::new();
        
        // Valid hosts
        assert!(validator.is_valid_host("localhost"));
        assert!(validator.is_valid_host("127.0.0.1"));
        assert!(validator.is_valid_host("0.0.0.0"));
        assert!(validator.is_valid_host("192.168.1.1"));
        assert!(validator.is_valid_host("example.com"));
        assert!(validator.is_valid_host("api.example.com"));
        
        // Invalid hosts
        assert!(!validator.is_valid_host(""));
        assert!(!validator.is_valid_host("invalid@host"));
        assert!(!validator.is_valid_host("host with spaces"));
    }
}
