use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose, Engine as _};

pub fn encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, &'static str> {
    let key = GenericArray::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message
    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|_| "encryption failed")?;
    Ok(ciphertext)
}

pub fn decrypt(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, &'static str> {
    let key = GenericArray::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(b"unique nonce");
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "decryption failed")?;
    Ok(plaintext)
}

pub fn decode_base64_key(encoded_key: &str) -> Result<[u8; 32], &'static str> {
    let decoded = general_purpose::STANDARD
        .decode(encoded_key)
        .map_err(|_| "invalid base64")?;
    if decoded.len() != 32 {
        return Err("invalid key length");
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}
