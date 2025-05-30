//! Library root for the `mmf-sigil-runtime` crate
//! Auto-generated to expose core modules under Rule Zero constraints

// Canonical state management
pub mod canon_loader;
pub mod canon_store;
pub mod canon_store_sled;
pub mod canon_store_sled_encrypted;
pub mod canon_diff_chain;
pub mod canon_init_tool;
pub mod canon_validator;

// Audit & trust
pub mod audit;
pub mod audit_chain;
pub mod audit_verifier;
pub mod trusted_knowledge;
pub mod elevation_verifier;
pub mod loa;

// License & seal tools
pub mod license_validator;
pub mod sealtool;

// Extensions & plugins
pub mod extensions;

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
pub mod narrative_irl_extension;

// Configuration & CLI
pub mod config;
pub mod config_loader;
pub mod cli;
pub mod sigilctl;

// Web server interface
pub mod sigilweb;
pub mod sigilweb_patched;

// Backup & recovery
pub mod backup_recovery;

// Session & runtime core
pub mod session_context;
pub mod sigil_runtime_core;
pub mod sigil_runtime_core_patch_with_irl;
pub mod sigil_session;

// Encryption & integrity
pub mod sigil_encrypt;
pub mod sigil_exporter;
pub mod sigil_integrity;
pub mod sigil_vault_encrypted;

// Protocol definitions
pub mod proto;
