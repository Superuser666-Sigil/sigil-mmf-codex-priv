/// CanonStore defines the trusted interface for Canon access.
/// Implementations must emit structured audit lines with chained hashes on all writes.
use crate::trusted_knowledge::TrustedKnowledgeEntry;
use crate::loa::LOA;
use crate::sigil_integrity::{verify_integrity, load_anchor_manifest, EntropyAnchor, IntegrityError};
use crate::audit::{AuditEvent, LogLevel};

pub type CanonStoreResult<T> = Result<T, CanonStoreError>;

/// Error types for CanonStore operations.
#[derive(Debug)]
pub enum CanonStoreError {
    NotFound(String),
    PermissionDenied(String),
    Serialization(String),
    Deserialization(String),
    Encryption(String),
    Decryption(String),
    Database(String),
    Integrity(IntegrityError),
}

/// Converts a canonical ID like 'canon::rust::nomicon::aliasing'
/// into a POSIX-safe path: 'canon/rust/nomicon/aliasing'
pub fn canon_id_to_path(id: &str) -> String {
    format!("/system/core/{}/integrity.anchor.yml", id.replace("::", "/"))
}

pub trait CanonStore {
    /// Write a knowledge entry to the Canon.
    pub fn write(&self, id: &str, entry: &TrustedKnowledgeEntry, loa: &LOA) -> CanonStoreResult<()>;

    /// Read a knowledge entry from the Canon by its ID and validate its integrity.
    pub fn read(&self, id: &str, loa: &LOA) -> CanonStoreResult<Option<TrustedKnowledgeEntry>> {
        // Load the raw entry blob using backend-specific logic
        let blob = self.load_blob(id)?; // <- implement in concrete struct

        // Load integrity anchor (from disk, embedded map, etc.)
        let manifest_path = canon_id_to_path(id);
        let anchor = match load_anchor_manifest(&manifest_path) {
            Ok(m) => m,
            Err(e) => {
                log::warn!("Failed to load anchor manifest for {}: {:?}", id, e);
                return Err(CanonStoreError::Integrity(IntegrityError::AnchorInvalid));
            }
        };

        // Verify integrity using sigil_integrity.rs
        verify_integrity(
            &blob,
            &anchor.entropy(),
            &anchor.hash,
            &anchor.witnesses,
            &anchor.anchors,
            anchor.required_loa,
        ).map_err(CanonStoreError::Integrity)?;

        // Deserialize into structured knowledge
        let entry: TrustedKnowledgeEntry = serde_json::from_slice(&blob)
            .map_err(|e| CanonStoreError::Deserialization(e.to_string()))?;

        Ok(Some(entry))
    }

    /// Backend-specific blob reader. NOT public API.
    pub fn load_blob(&self, id: &str) -> Result<Vec<u8>, CanonStoreError>;
}