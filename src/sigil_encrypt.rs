use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::{Engine as _, engine::general_purpose};
use rand::RngCore;
use rand::rngs::OsRng;

pub fn encrypt(data: &[u8], key: &[u8]) -> Result<(Vec<u8>, [u8; 12]), &'static str> {
    let key = GenericArray::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let mut nonce_bytes = [0u8; 12];
    let mut rng = OsRng;
    rng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), data)
        .map_err(|_| "encryption failed")?;
    Ok((ciphertext, nonce_bytes))
}

pub fn decrypt(ciphertext: &[u8], key: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>, &'static str> {
    let key = GenericArray::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
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
