//! Library root for the `mmf-sigil-runtime` crate
//! Auto-generated to expose core modules under Rule Zero constraints

// Core error handling
pub mod errors;

// Canonical state management
pub mod canon_diff_chain;
pub mod canon_guard;
pub mod canon_init_tool;
pub mod canon_loader;
pub mod canon_store;
pub mod canon_store_codex_nexus;
pub mod canon_store_sled;
pub mod canon_store_sled_encrypted;
pub mod canon_validator;

// Audit & trust
pub mod audit;
pub mod audit_chain;
pub mod audit_store;
pub mod audit_verifier;
pub mod elevation_verifier;
pub mod loa;
pub mod trust_registry;
pub mod trusted_knowledge;
pub mod secure_audit_chain;

// New security and trust modules
pub mod trust_linear;
pub mod quorum_system;

// License & seal tools
pub mod key_manager;
pub mod license_validator;
pub mod sealtool;

// Extensions & plugins
pub mod extension_runtime;
pub mod extensions;
pub mod module_loader;
pub mod module_scope;

// Runtime configuration
pub mod runtime_config;

// Configuration & CLI
pub mod cli;
pub mod config;
pub mod config_loader;
pub mod config_security;
pub mod sigilctl;

// Web server interface
pub mod sigilweb;

// Backup & recovery
pub mod backup_recovery;

// Session & runtime core
pub mod session_context;
pub mod sigil_runtime_core;

pub mod input_validator;
pub mod sigil_session;


// Platform optimizations
pub mod platform_optimizations;

// Security protections
pub mod rate_limiter;
pub mod csrf_protection;
pub mod secure_file_ops;

// Encryption & integrity
pub mod sigil_encrypt;
pub mod sigil_exporter;
pub mod sigil_integrity;
pub mod sigil_vault;
pub mod sigil_vault_encrypted;

// Canonical record representation for Codex Nexus
pub mod canonical_record;

// JSON Canonicalization Scheme (RFC 8785)
pub mod canonicalize;

// Persistent Ed25519 key management
pub mod keys;

// Witness registry for trusted public keys
pub mod witness_registry;

// Logging
pub mod log_sink;



#[cfg(test)]
mod tests {
    pub mod audit_chain_test;
    pub mod canon_store;
    pub mod security_tests;
    pub mod module_tests;
    pub mod module_integration_test;
    pub mod module_execution_comprehensive_test;
    pub mod quorum_enforcement_test;
    pub mod quorum_interactive_workflow_test;
    pub mod key_lifecycle_test;
}

// Re-export key types for the two-phase ReasoningChain -> FrozenChain approach
pub use audit_chain::{
    CryptographicWitness, // Cryptographic verification
    FrozenChain,          // Phase 2: Immutable record for cryptographic integrity
    IRLInfo,              // Trust scoring
    InputSnapshot,        // Immutable input data
    OutputSnapshot,       // Immutable output data
    ReasoningChain,       // Phase 1: Mutable process for "thinking out loud"
    ReasoningTrace,       // Immutable reasoning steps
    TrainingMetadata,     // ML training metadata
    Verdict,              // Decision outcomes
};

pub use audit_store::AuditStore; // Storage for both phases
