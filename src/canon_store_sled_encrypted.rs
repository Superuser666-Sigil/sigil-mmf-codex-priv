use crate::canon_store::CanonStore;
use crate::loa::{LOA, can_read_canon, can_write_canon};
use crate::sigil_encrypt::{decode_base64_key, decrypt, encrypt};
use crate::trusted_knowledge::TrustedKnowledgeEntry;
use serde_json;
use sled::Db;
use std::convert::TryInto;

pub struct CanonStoreSled {
    db: Db,
}

impl CanonStoreSled {
    pub fn new(path: &str) -> Self {
        let db = sled::open(path).expect("Failed to open sled database");
        Self { db }
    }
}

impl CanonStore for CanonStoreSled {
    fn load_entry(&self, key: &str, loa: &LOA) -> Option<TrustedKnowledgeEntry> {
        if !can_read_canon(loa) {
            return None;
        }

        self.db.get(key).ok().flatten().and_then(|ivec| {
            let key_opt = std::env::var("SIGIL_AES_KEY")
                .ok()
                .and_then(|k| decode_base64_key(&k).ok());
            let data = if let Some(key) = key_opt {
                if ivec.len() >= 12 {
                    let (nonce_bytes, ciphertext) = ivec.split_at(12);
                    let nonce: [u8; 12] = nonce_bytes.try_into().unwrap();
                    decrypt(ciphertext, &key, &nonce).unwrap_or_else(|_| ivec.to_vec())
                } else {
                    ivec.to_vec()
                }
            } else {
                ivec.to_vec()
            };
            serde_json::from_slice::<TrustedKnowledgeEntry>(&data).ok()
        })
    }

    fn add_entry(
        &mut self,
        entry: TrustedKnowledgeEntry,
        loa: &LOA,
        _allow_operator_write: bool,
    ) -> Result<(), &'static str> {
        if !can_write_canon(loa) {
            return Err("Insufficient LOA to write canon entry");
        }

        let serialized = serde_json::to_vec(&entry).map_err(|_| "Serialization failed")?;
        let encrypted = if entry.verdict == crate::trusted_knowledge::SigilVerdict::Allow {
            if let Some(key) = std::env::var("SIGIL_AES_KEY")
                .ok()
                .and_then(|k| decode_base64_key(&k).ok())
            {
                let (ciphertext, nonce) =
                    encrypt(&serialized, &key).map_err(|_| "Canon encryption failed")?;
                let mut out = nonce.to_vec();
                out.extend_from_slice(&ciphertext);
                out
            } else {
                serialized
            }
        } else {
            serialized
        };

        self.db
            .insert(entry.id.as_str(), encrypted)
            .map_err(|_| "Write failed")?;
        Ok(())
    }

    fn list_entries(&self, category: Option<&str>, loa: &LOA) -> Vec<TrustedKnowledgeEntry> {
        if !can_read_canon(loa) {
            return vec![];
        }

        self.db
            .iter()
            .filter_map(|item| item.ok())
            .filter_map(|(_, val)| serde_json::from_slice::<TrustedKnowledgeEntry>(&val).ok())
            .filter(|entry| category.is_none_or(|cat| entry.category == cat))
            .collect()
    }
}
