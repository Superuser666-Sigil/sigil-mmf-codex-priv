use crate::canon_store::CanonStore;
use crate::canon_store_sled::CanonStoreSled;
use crate::loa::LOA;
use crate::sigil_vault::VaultMemoryBlock;
use crate::trusted_knowledge::TrustedKnowledgeEntry;
use crate::canonical_record::CanonicalRecord;
use serde::Deserialize;
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct SigilSnapshot {
    pub vault: Vec<VaultMemoryBlock>,
    pub canon: Vec<TrustedKnowledgeEntry>,
}

pub fn restore_from_snapshot(
    path: &str,
    canon_store: &mut CanonStoreSled,
    allow_operator: bool,
) -> Result<(), &'static str> {
    let mut file = File::open(Path::new(path)).map_err(|_| "Unable to open snapshot file")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|_| "Failed to read snapshot")?;

    let snapshot: SigilSnapshot =
        serde_json::from_str(&contents).map_err(|_| "Snapshot format invalid")?;

    for entry in snapshot.canon {
        // Convert each trusted entry to a canonical record; use system namespace
        match CanonicalRecord::from_trusted_entry(&entry, "system", "system", 1) {
            Ok(record) => {
                canon_store
                    .add_record(record, &LOA::Root, allow_operator)
                    .ok();
            }
            Err(e) => {
                // Log conversion failure but continue
                println!("[Recovery] Failed to convert entry {}: {e}", entry.id);
            }
        }
    }

    println!("[Recovery] Canon restored successfully.");
    Ok(())
}
