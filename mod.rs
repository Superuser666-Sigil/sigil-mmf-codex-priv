//! MMF + Sigil IRL Subsystem Module Registry
//! Registers trust-scoring and explainability subsystems with full Canon enforcement

pub mod irl_data_pipeline;      // Ingests IRL traces for telemetry or learning
pub mod irl_feature_store;      // Caches runtime feature vectors per trace
pub mod irl_telemetry;          // Streams ExplanationTraces to logs, vaults, or telemetry targets
pub mod irl_explainer;          // Generates IRL-backed justifications for trust decisions
pub mod irl_versioning;         // Provides IRL version metadata and schema validation
pub mod irl_modes;              // Defines runtime IRL mode flags (e.g., AuditOnly, Strict)
pub mod narrative_irl_extension; // Optional extension for narrative-aware trust shaping (experimental)
