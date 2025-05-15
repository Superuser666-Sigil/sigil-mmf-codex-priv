// Canon-Compliant sigil_encrypt.rs
// Purpose: Provide AES-256-GCM encryption, Ed25519 sealing, and cryptographic traceability for MMF + Sigil

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use aes_gcm::aead::rand_core::RngCore;
use base64::{engine::general_purpose, Engine as _};
use chrono::{Utc, DateTime};
use ed25519_dalek::{Keypair, Signature, Signer, Verifier, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use crate::audit::{AuditEvent, LogLevel};

pub const IV_LEN: usize = 12;
pub const KEY_LEN: usize = 32; // 256-bit AES key

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SealedPayload {
    pub ciphertext: Vec<u8>,
    pub iv: Vec<u8>,
    pub hash: String,
    pub signature: String,
    pub signed_by: String,
    pub sealed_at: DateTime<Utc>,
}

#[derive(Debug)]
pub enum SigilCryptoError {
    InvalidKeyLength,
    EncryptionFailed,
    DecryptionFailed,
    Base64DecodeError,
    SignatureVerificationFailed,
    IoError(String),
    SerializationError(String),
}

pub fn encrypt_and_seal(
    plaintext: &[u8],
    aes_key: &[u8],
    signer: &Keypair,
    signer_label: &str,
) -> Result<(SealedPayload, AuditEvent), SigilCryptoError> {
    if aes_key.len() != KEY_LEN {
        return Err(SigilCryptoError::InvalidKeyLength);
    }

    let cipher = Aes256Gcm::new(Key::from_slice(aes_key));
    let mut iv = [0u8; IV_LEN];
    OsRng.fill_bytes(&mut iv);
    let nonce = Nonce::from_slice(&iv);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| SigilCryptoError::EncryptionFailed)?;

    let mut digest = Sha256::new();
    digest.update(&ciphertext);
    let hash = format!("{:x}", digest.finalize());

    let signature = signer
        .try_sign(&ciphertext)
        .map_err(|_| SigilCryptoError::SignatureVerificationFailed)?;

    let sealed = SealedPayload {
        ciphertext,
        iv: iv.to_vec(),
        hash: hash.clone(),
        signature: base64::encode(signature.to_bytes()),
        signed_by: signer_label.into(),
        sealed_at: Utc::now(),
    };

    let audit = AuditEvent::new(
        signer_label,
        "encrypt_and_seal",
        &hash,
        "sigil_encrypt.rs",
    )
    .with_severity(LogLevel::Info)
    .with_context("AES-GCM encryption and Ed25519 seal applied to payload");

    Ok((sealed, audit))
}

pub fn decrypt_and_verify(
    payload: &SealedPayload,
    aes_key: &[u8],
    pubkey_bytes: &[u8],
) -> Result<Vec<u8>, SigilCryptoError> {
    if aes_key.len() != KEY_LEN {
        return Err(SigilCryptoError::InvalidKeyLength);
    }

    let pubkey = ed25519_dalek::PublicKey::from_bytes(pubkey_bytes)
        .map_err(|_| SigilCryptoError::SignatureVerificationFailed)?;

    let signature_bytes = base64::decode(&payload.signature)
        .map_err(|_| SigilCryptoError::Base64DecodeError)?;
    let signature = Signature::from_bytes(&signature_bytes)
        .map_err(|_| SigilCryptoError::SignatureVerificationFailed)?;

    pubkey
        .verify(&payload.ciphertext, &signature)
        .map_err(|_| SigilCryptoError::SignatureVerificationFailed)?;

    let cipher = Aes256Gcm::new(Key::from_slice(aes_key));
    let nonce = Nonce::from_slice(&payload.iv);

    cipher
        .decrypt(nonce, payload.ciphertext.as_ref())
        .map_err(|_| SigilCryptoError::DecryptionFailed)
}

pub fn decode_base64_key(encoded: &str) -> Result<[u8; KEY_LEN], SigilCryptoError> {
    let raw = general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| SigilCryptoError::Base64DecodeError)?;

    if raw.len() != KEY_LEN {
        return Err(SigilCryptoError::InvalidKeyLength);
    }

    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&raw);
    Ok(key)
}
