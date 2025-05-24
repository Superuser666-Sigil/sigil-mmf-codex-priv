// Canon-Compliant sigil_vault_encrypted.rs
// Purpose: Secure LOA-aware vault for runtime memory with AES-GCM encryption and audit traceability

use chrono::{Utc, DateTime};
use serde::{Deserialize, Serialize};
use std::fs::{File};
use std::io::{Read, Write};
use std::path::Path;

use crate::audit::{AuditEvent, LogLevel};
use crate::loa::LOA;
use crate::sigil_encrypt::{encrypt_and_seal, decrypt_and_verify, SealedPayload, SigilCryptoError};
use ed25519_dalek::Keypair;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultMemoryBlock {
    pub id: String,
    pub session_id: String,
    pub mnemonic: String,
    pub loa: LOA,
    pub content: String,
    pub deleted: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct VaultResult {
    pub success: bool,
    pub message: String,
    pub audit: AuditEvent,
    pub sealed: Option<SealedPayload>,
    pub blocks: Vec<VaultMemoryBlock>,
}

pub struct SigilVault {
    pub blocks: Vec<VaultMemoryBlock>,
    pub signer: Keypair,
    pub signer_label: String,
    pub aes_key: [u8; 32],
}

impl SigilVault {
    pub fn new(aes_key: [u8; 32], signer: Keypair, signer_label: &str) -> Self {
        Self {
            blocks: Vec::new(),
            signer,
            signer_label: signer_label.into(),
            aes_key,
        }
    }

    pub fn add_block(&mut self, block: VaultMemoryBlock) -> VaultResult {
        let audit = AuditEvent::new(
            &block.mnemonic,
            "vault_add_block",
            &block.id,
            "sigil_vault_encrypted.rs"
        )
        .with_severity(LogLevel::Info)
        .with_context(format!("Block LOA = {:?}", block.loa));

        self.blocks.push(block.clone());

        VaultResult {
            success: true,
            message: "Block added to vault".into(),
            audit,
            sealed: None,
            blocks: vec![block],
        }
    }

    pub fn save(&self, out_path: &str) -> Result<VaultResult, String> {
        let json = serde_json::to_vec(&self.blocks)
            .map_err(|e| format!("Vault serialization failed: {}", e))?;

        let (sealed, audit) = encrypt_and_seal(&json, &self.aes_key, &self.signer, &self.signer_label)
            .map_err(|e| format!("Encryption failed: {:?}", e))?;

        let out_file = File::create(out_path)
            .map_err(|e| format!("Vault write failed: {}", e))?;
        serde_json::to_writer_pretty(out_file, &sealed)
            .map_err(|e| format!("Vault output error: {}", e))?;

        Ok(VaultResult {
            success: true,
            message: "Vault saved and sealed.".into(),
            audit,
            sealed: Some(sealed),
            blocks: vec![],
        })
    }

    pub fn load(&mut self, in_path: &str, pubkey_bytes: &[u8]) -> Result<VaultResult, String> {
        let mut file = File::open(in_path)
            .map_err(|e| format!("Vault read failed: {}", e))?;
        let mut content = String::new();
        file.read_to_string(&mut content)
            .map_err(|e| format!("Vault read error: {}", e))?;

        let sealed: SealedPayload = serde_json::from_str(&content)
            .map_err(|e| format!("Vault decode error: {}", e))?;

        let decrypted = decrypt_and_verify(&sealed, &self.aes_key, pubkey_bytes)
            .map_err(|e| format!("Decryption failed: {:?}", e))?;

        let blocks: Vec<VaultMemoryBlock> = serde_json::from_slice(&decrypted)
            .map_err(|e| format!("Vault structure error: {}", e))?;

        let audit = AuditEvent::new(
            &self.signer_label,
            "vault_load",
            &sealed.hash,
            "sigil_vault_encrypted.rs"
        )
        .with_severity(LogLevel::Info)
        .with_context(format!("Vault loaded with {} blocks", blocks.len()));

        self.blocks = blocks.clone();

        Ok(VaultResult {
            success: true,
            message: "Vault loaded and verified.".into(),
            audit,
            sealed: Some(sealed),
            blocks,
        })
    }
}
