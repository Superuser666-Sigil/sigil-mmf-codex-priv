use crate::canon_store::CanonStore;
use crate::canonical_record::CanonicalRecord;
use crate::errors::{SigilError, SigilResult};
use crate::loa::{LOA, can_read_canon, can_write_canon};
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
    fn add_record(
        &mut self,
        record: CanonicalRecord,
        loa: &LOA,
        _allow_operator_write: bool,
    ) -> Result<(), &'static str> {
        // Enforce write permission based on LOA
        if !can_write_canon(loa) {
            return Err("Insufficient LOA to write canon record");
        }
        let bytes = serde_json::to_vec(&record).map_err(|e| {
            error!("Failed to serialize canon record {}: {}", record.id, e);
            "serialization_failed"
        })?;
        self.db
            .insert(record.id.as_bytes(), bytes)
            .map(|_| {
                info!("Successfully added canon record: {}", record.id);
            })
            .map_err(|e| {
                error!("Failed to insert canon record {}: {}", record.id, e);
                "sled_insert_failed"
            })
    }

    fn load_record(&self, key: &str, loa: &LOA) -> Option<CanonicalRecord> {
        if !can_read_canon(loa) {
            return None;
        }
        match self.db.get(key) {
            Ok(Some(bytes)) => match serde_json::from_slice::<CanonicalRecord>(&bytes) {
                Ok(record) => {
                    info!("Successfully loaded canon record: {key}");
                    Some(record)
                }
                Err(e) => {
                    error!("Failed to deserialize canon record {key}: {e}");
                    None
                }
            },
            Ok(None) => {
                warn!("Canon record not found: {key}");
                None
            }
            Err(e) => {
                error!("Database error loading canon record {key}: {e}");
                None
            }
        }
    }

    fn list_records(&self, kind: Option<&str>, loa: &LOA) -> Vec<CanonicalRecord> {
        if !can_read_canon(loa) {
            return vec![];
        }
        let mut records = Vec::new();
        let mut error_count = 0;
        for item in self.db.iter().values() {
            match item {
                Ok(bytes) => match serde_json::from_slice::<CanonicalRecord>(&bytes) {
                    Ok(record) => {
                        if kind.is_none() || kind.map(|k| record.kind == k).unwrap_or(false) {
                            records.push(record);
                        }
                    }
                    Err(e) => {
                        error_count += 1;
                        if error_count <= 5 {
                            error!("Failed to deserialize canon record during listing: {e}");
                        }
                    }
                },
                Err(e) => {
                    error_count += 1;
                    if error_count <= 5 {
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
            "Listed {} canon records for kind: {:?}",
            records.len(),
            kind
        );
        records
    }
}
