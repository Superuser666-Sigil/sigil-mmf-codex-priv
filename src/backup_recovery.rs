
use std::fs::File;
use std::io::{Read};
use std::path::Path;
use serde::{Deserialize};
use crate::trusted_knowledge::TrustedKnowledgeEntry;
use crate::sigil_vault::VaultMemoryBlock;
use crate::canon_store::CanonStore;
use crate::canon_store_sled::CanonStoreSled;
use crate::loa::LOA;

#[derive(Debug, Deserialize)]
pub struct SigilSnapshot {
    pub vault: Vec<VaultMemoryBlock>,
    pub canon: Vec<TrustedKnowledgeEntry>,
}

pub fn restore_from_snapshot(path: &str, canon_store: &mut CanonStoreSled, allow_operator: bool) -> Result<(), &'static str> {
    let mut file = File::open(Path::new(path)).map_err(|_| "Unable to open snapshot file")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).map_err(|_| "Failed to read snapshot")?;

    let snapshot: SigilSnapshot = serde_json::from_str(&contents).map_err(|_| "Snapshot format invalid")?;

    for entry in snapshot.canon {
        canon_store.add_entry(entry, &LOA::Root, allow_operator).ok();
    }

    println!("[Recovery] Canon restored successfully.");
    Ok(())
}
