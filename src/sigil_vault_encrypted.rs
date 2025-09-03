use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryInto;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use uuid::Uuid;

use crate::loa::LOA;
use crate::sigil_encrypt::{decode_base64_key, decrypt, encrypt};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VaultMemoryBlock {
    pub id: String,
    pub session_id: String,
    pub mnemonic: Option<String>,
    pub loa: LOA,
    pub content: String,
    pub deleted: bool,
}

pub struct SigilVault {
    storage_path: String,
    memory: HashMap<String, VaultMemoryBlock>,
}

impl SigilVault {
    pub fn new(path: &str) -> Self {
        let mut memory = HashMap::new();
        if Path::new(path).exists()
            && let Ok(mut file) = File::open(path)
        {
            let key_opt = std::env::var("SIGIL_AES_KEY")
                .ok()
                .and_then(|k| decode_base64_key(&k).ok());

            let mut raw = Vec::new();
            if file.read_to_end(&mut raw).is_ok() {
                let decrypted = if let Some(key) = key_opt {
                    if raw.len() >= 12 {
                        let (nonce_bytes, ciphertext) = raw.split_at(12);
                        let nonce: [u8; 12] = nonce_bytes.try_into().unwrap();
                        decrypt(ciphertext, &key, &nonce).unwrap_or_else(|_| vec![])
                    } else {
                        vec![]
                    }
                } else {
                    raw
                };
                if let Ok(loaded) = serde_json::from_slice::<Vec<VaultMemoryBlock>>(&decrypted) {
                    for block in loaded {
                        memory.insert(block.id.clone(), block);
                    }
                }
            }
        }

        SigilVault {
            storage_path: path.into(),
            memory,
        }
    }

    pub fn add_block(
        &mut self,
        session_id: &str,
        mnemonic: Option<String>,
        loa: &LOA,
        content: &str,
    ) -> String {
        let id = Uuid::new_v4().to_string();
        let block = VaultMemoryBlock {
            id: id.clone(),
            session_id: session_id.into(),
            mnemonic,
            loa: loa.clone(),
            content: content.into(),
            deleted: false,
        };
        self.memory.insert(id.clone(), block);
        self.persist().ok(); // Fail silently
        id
    }

    pub fn get_block(&self, id: &str, loa: &LOA) -> Option<&VaultMemoryBlock> {
        self.memory.get(id).filter(|b| !b.deleted && loa >= &b.loa)
    }

    pub fn soft_delete(&mut self, id: &str, session_id: &str) -> bool {
        if let Some(block) = self.memory.get_mut(id)
            && block.session_id == session_id
            && !block.deleted
        {
            block.deleted = true;
            self.persist().ok(); // Fail silently
            return true;
        }
        false
    }

    fn persist(&self) -> Result<(), &'static str> {
        let key_opt = std::env::var("SIGIL_AES_KEY")
            .ok()
            .and_then(|k| decode_base64_key(&k).ok());

        let vec: Vec<_> = self
            .memory
            .values()
            .filter(|b| !b.deleted)
            .cloned()
            .collect();

        let serialized = serde_json::to_vec(&vec).map_err(|_| "Serialization error")?;
        let encrypted = if let Some(key) = key_opt {
            let (ciphertext, nonce) = encrypt(&serialized, &key).map_err(|_| "Encryption error")?;
            let mut out = nonce.to_vec();
            out.extend_from_slice(&ciphertext);
            out
        } else {
            serialized
        };

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.storage_path)
            .map_err(|_| "Vault file open error")?;
        file.write_all(&encrypted).map_err(|_| "Vault write error")
    }
}
