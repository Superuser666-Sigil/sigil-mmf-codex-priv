use crate::canon_store::CanonStore;
use crate::errors::{SigilError, SigilResult};
use crate::loa::LOA;
use crate::trusted_knowledge::TrustedKnowledgeEntry;
use log::{error, info, warn};
use sled::Db;
use std::sync::Arc;

pub struct CanonStoreSled {
    db: Arc<Db>,
}

impl CanonStoreSled {
    pub fn new(path: &str) -> SigilResult<Self> {
        let db = sled::open(path).map_err(|e| SigilError::database("opening sled database", e))?;

        info!("Successfully opened sled database at: {path}");
        Ok(CanonStoreSled { db: Arc::new(db) })
    }
}

impl CanonStore for CanonStoreSled {
    fn add_entry(
        &mut self,
        entry: TrustedKnowledgeEntry,
        _loa: &LOA,
        _allow_operator_write: bool,
    ) -> Result<(), &'static str> {
        let entry_bytes = serde_json::to_vec(&entry).map_err(|e| {
            error!("Failed to serialize canon entry {}: {}", entry.id, e);
            "serialization_failed"
        })?;

        self.db
            .insert(entry.id.as_bytes(), entry_bytes)
            .map(|_| {
                info!("Successfully added canon entry: {}", entry.id);
            })
            .map_err(|e| {
                error!("Failed to insert canon entry {}: {}", entry.id, e);
                "sled_insert_failed"
            })
    }

    fn load_entry(&self, key: &str, _loa: &LOA) -> Option<TrustedKnowledgeEntry> {
        match self.db.get(key) {
            Ok(Some(bytes)) => match serde_json::from_slice(&bytes) {
                Ok(entry) => {
                    info!("Successfully loaded canon entry: {key}");
                    Some(entry)
                }
                Err(e) => {
                    error!("Failed to deserialize canon entry {key}: {e}");
                    None
                }
            },
            Ok(None) => {
                warn!("Canon entry not found: {key}");
                None
            }
            Err(e) => {
                error!("Database error loading canon entry {key}: {e}");
                None
            }
        }
    }

    fn list_entries(&self, category: Option<&str>, _loa: &LOA) -> Vec<TrustedKnowledgeEntry> {
        let mut entries = Vec::new();
        let mut error_count = 0;

        for item in self.db.iter().values() {
            match item {
                Ok(bytes) => {
                    match serde_json::from_slice::<TrustedKnowledgeEntry>(&bytes) {
                        Ok(entry) => {
                            if category.is_none_or(|c| entry.category == c) {
                                entries.push(entry);
                            }
                        }
                        Err(e) => {
                            error_count += 1;
                            if error_count <= 5 {
                                // Limit error logging
                                error!("Failed to deserialize canon entry during listing: {e}");
                            }
                        }
                    }
                }
                Err(e) => {
                    error_count += 1;
                    if error_count <= 5 {
                        // Limit error logging
                        error!("Database error during listing: {e}");
                    }
                }
            }
        }

        if error_count > 5 {
            warn!(
                "Encountered {} additional errors during canon listing",
                error_count - 5
            );
        }

        info!(
            "Listed {} canon entries for category: {:?}",
            entries.len(),
            category
        );
        entries
    }
}
