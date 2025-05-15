// Phase 1 - Canon Extension: canon_store.rs
// Purpose: Trusted access layer for canonical Sigil data with traceability and enforcement

use crate::loa::{LOA, can_read_canon, can_write_canon};
use crate::trusted_knowledge::TrustedKnowledgeEntry;
use crate::audit::{AuditEvent, LogLevel};
use chrono::{DateTime, Utc};
use serde::Serialize;

/// Enum describing failures in CanonStore operations
#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CanonStoreError {
    UnauthorizedRead,
    UnauthorizedWrite,
    EntryNotFound,
    StorageFailure,
    InvalidCategory,
    AuditFailed,
}

/// Struct returned by all read/write operations, including audit and trust context
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonStoreResult<T> {
    pub data: Option<T>,
    pub audit: Option<AuditEvent>,
    pub irl_score: Option<f32>,
    pub success: bool,
    pub message: String,
    pub timestamp: DateTime<Utc>,
}

/// CanonStore defines access and mutation behavior for canonical runtime knowledge
pub trait CanonStore {
    /// Loads a single canon entry if LOA permits it
    fn load_entry(
        &self,
        key: &str,
        loa: &LOA,
        trace_id: Option<String>,
        source: Option<&str>,
    ) -> Result<CanonStoreResult<TrustedKnowledgeEntry>, CanonStoreError>;

    /// Adds or replaces a canon entry, applying enforcement policies and optional audit trace
    fn add_entry(
        &mut self,
        entry: TrustedKnowledgeEntry,
        loa: &LOA,
        allow_operator_write: bool,
        trace_id: Option<String>,
        source: Option<&str>,
    ) -> Result<CanonStoreResult<()>, CanonStoreError>;

    /// Returns all canon entries matching a category if LOA allows access
    fn list_entries(
        &self,
        category: Option<&str>,
        loa: &LOA,
        trace_id: Option<String>,
        source: Option<&str>,
    ) -> Result<CanonStoreResult<Vec<TrustedKnowledgeEntry>>, CanonStoreError>;
}
