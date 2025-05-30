
use aes_gcm::{aead::{Aead, KeyInit, OsRng}, Aes256Gcm, Key, Nonce};
use aes_gcm::aead::rand_core::RngCore;
use base64::{engine::general_purpose, Engine as _};

const IV_LEN: usize = 12;
const KEY_LEN: usize = 32; // 256-bit key

pub fn encrypt(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, &'static str> {
    if key.len() != KEY_LEN {
        return Err("Key must be 32 bytes (256-bit)");
    }

    let cipher = Aes256Gcm::new(Key::from_slice(key));
    let mut iv = [0u8; IV_LEN];
    OsRng.fill_bytes(&mut iv);
    let nonce = Nonce::from_slice(&iv);

    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|_| "Encryption failed")?;

    let mut result = Vec::with_capacity(IV_LEN + ciphertext.len());
    result.extend_from_slice(&iv);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

pub fn decrypt(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, &'static str> {
    if key.len() != KEY_LEN {
        return Err("Key must be 32 bytes (256-bit)");
    }

    if ciphertext.len() < IV_LEN {
        return Err("Ciphertext too short");
    }

    let (iv, data) = ciphertext.split_at(IV_LEN);
    let cipher = Aes256Gcm::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(iv);

    cipher.decrypt(nonce, data)
        .map_err(|_| "Decryption failed")
}

pub fn decode_base64_key(encoded: &str) -> Result<[u8; KEY_LEN], &'static str> {
    let raw = general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| "Base64 decode failed")?;

    if raw.len() != KEY_LEN {
        return Err("Decoded key must be 32 bytes");
    }

    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&raw);
    Ok(key)
}
