//! Library root for the `mmf-sigil-runtime` crate
//! Auto-generated to expose core modules under Rule Zero constraints

// Core error handling
pub mod errors;

// Canonical state management
pub mod canon_loader;
pub mod canon_store;
pub mod canon_store_sled;
pub mod canon_store_sled_encrypted;
pub mod canon_store_codex_nexus;
pub mod canon_diff_chain;
pub mod canon_init_tool;
pub mod canon_validator;
pub mod canon_guard;

// Audit & trust
pub mod audit;
pub mod audit_chain;
pub mod audit_store;
pub mod audit_verifier;
pub mod trusted_knowledge;
pub mod elevation_verifier;
pub mod loa;
pub mod trust_registry;

// License & seal tools
pub mod license_validator;
pub mod sealtool;
pub mod key_manager;

// Extensions & plugins
pub mod extensions;
pub mod extension_runtime;
pub mod module_loader;
pub mod module_scope;

// IRL (In Real Life) data pipeline and executors
pub mod irl_data_pipeline;
pub mod irl_executor;
pub mod irl_explainer;
pub mod irl_feature_store;
pub mod irl_modes;
pub mod irl_telemetry;
pub mod irl_versioning;
pub mod irl_runtime;
pub mod irl_train_tool;
pub mod irl_trust_evaluator;
pub mod irl_reward;
pub mod irl_adapter;

// Configuration & CLI
pub mod config;
pub mod config_loader;
pub mod cli;
pub mod sigilctl;

// Web server interface
pub mod sigilweb;

// Backup & recovery
pub mod backup_recovery;

// Session & runtime core
pub mod session_context;
pub mod sigil_runtime_core;
pub mod sigil_runtime_core_patch_with_irl;
pub mod sigil_session;
pub mod sigilirl;

// Encryption & integrity
pub mod sigil_encrypt;
pub mod sigil_exporter;
pub mod sigil_integrity;
pub mod sigil_vault;
pub mod sigil_vault_encrypted;

// Logging
pub mod log_sink;

// Protocol definitions
pub mod proto;

// Re-export key types for the two-phase ReasoningChain -> FrozenChain approach
pub use audit_chain::{
    ReasoningChain,      // Phase 1: Mutable process for "thinking out loud"
    FrozenChain,         // Phase 2: Immutable record for cryptographic integrity
    InputSnapshot,       // Immutable input data
    ReasoningTrace,      // Immutable reasoning steps
    OutputSnapshot,      // Immutable output data
    TrainingMetadata,    // ML training metadata
    CryptographicWitness, // Cryptographic verification
    Verdict,            // Decision outcomes
    IRLInfo,            // Trust scoring
};

pub use audit_store::AuditStore; // Storage for both phases
