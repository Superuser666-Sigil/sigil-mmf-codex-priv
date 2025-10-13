use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Key, OsRng, generic_array::GenericArray},
};
use argon2::{
    Argon2, PasswordHasher, PasswordVerifier,
    password_hash::{PasswordHash, SaltString},
};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use std::{
    fs, io,
    path::{Path, PathBuf},
};
use thiserror::Error;

const MAGIC: &[u8; 8] = b"MMFKEYv1";

#[derive(Debug, Error)]
pub enum KeywrapError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("argon2: {0}")]
    Argon(String),
    #[error("crypto error")]
    Crypto,
    #[error("format error")]
    Format,
}

impl From<argon2::password_hash::Error> for KeywrapError {
    fn from(err: argon2::password_hash::Error) -> Self {
        KeywrapError::Argon(err.to_string())
    }
}

pub struct KeyStore {
    dir: PathBuf, // e.g. /var/lib/mmf/keys
}

impl KeyStore {
    pub fn new<P: AsRef<Path>>(dir: P) -> Self {
        Self {
            dir: dir.as_ref().to_path_buf(),
        }
    }

    pub fn ensure_dir(&self) -> Result<(), KeywrapError> {
        if !self.dir.exists() {
            fs::create_dir_all(&self.dir)?;
        }
        Ok(())
    }

    fn file(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// Create or load an encrypted Ed25519 private key (seed) wrapped by a passphrase.
    pub fn load_or_create_ed25519(
        &self,
        name: &str,
        passphrase: &str,
    ) -> Result<(ed25519_dalek::SigningKey, String), KeywrapError> {
        self.ensure_dir()?;
        let path = self.file(name);
        if path.exists() {
            let bytes = fs::read(&path)?;
            let (sk, pk_b64) = decrypt_key(&bytes, passphrase)?;
            return Ok((sk, pk_b64));
        }

        // Generate new ed25519 key
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let pk_b64 = B64.encode(sk.verifying_key().to_bytes());
        let seed = sk.to_keypair_bytes(); // 64 bytes (seed + pk); we'll wrap the secret part
        let wrapped = encrypt_key(&seed[..32], passphrase)?; // first 32 bytes are the secret seed
        fs::write(&path, wrapped)?;
        // zeroize the secret bytes in memory
        let mut secret = seed[..32].to_vec();
        secret.zeroize();
        Ok((sk, pk_b64))
    }
}

/// File format:
/// MAGIC(8) || salt_len(2) || salt || nonce(12) || argon2_hash_str_len(2) || argon2_hash_str || ciphertext
fn encrypt_key(secret_seed: &[u8], passphrase: &str) -> Result<Vec<u8>, KeywrapError> {
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    let argon = Argon2::default();

    // Store a hash string too (for passphrase validation)
    let hash_str = argon
        .hash_password(passphrase.as_bytes(), &salt)?
        .to_string();

    // Derive AES key from passphrase+salt via SHA256(passphrase || salt)
    let mut hasher = Sha256::new();
    hasher.update(passphrase.as_bytes());
    hasher.update(salt.as_str().as_bytes());
    let key_bytes = hasher.finalize();
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);

    let cipher = Aes256Gcm::new(key);
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(GenericArray::from_slice(&nonce), secret_seed)
        .map_err(|_| KeywrapError::Crypto)?;

    // layout
    let mut out = Vec::with_capacity(
        8 + 2 + salt.as_str().len() + 12 + 2 + hash_str.len() + ciphertext.len(),
    );
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(salt.as_str().len() as u16).to_be_bytes());
    out.extend_from_slice(salt.as_str().as_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&(hash_str.len() as u16).to_be_bytes());
    out.extend_from_slice(hash_str.as_bytes());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt_key(
    bytes: &[u8],
    passphrase: &str,
) -> Result<(ed25519_dalek::SigningKey, String), KeywrapError> {
    let mut pos = 0;
    if bytes.len() < 8 || &bytes[0..8] != MAGIC {
        return Err(KeywrapError::Format);
    }
    pos += 8;

    let salt_len = u16::from_be_bytes(bytes[pos..pos + 2].try_into().unwrap()) as usize;
    pos += 2;
    let salt_str =
        std::str::from_utf8(&bytes[pos..pos + salt_len]).map_err(|_| KeywrapError::Format)?;
    pos += salt_len;

    let nonce = &bytes[pos..pos + 12];
    pos += 12;

    let ph_len = u16::from_be_bytes(bytes[pos..pos + 2].try_into().unwrap()) as usize;
    pos += 2;
    let ph_str =
        std::str::from_utf8(&bytes[pos..pos + ph_len]).map_err(|_| KeywrapError::Format)?;
    pos += ph_len;

    let ciphertext = &bytes[pos..];

    // verify passphrase quickly
    let parsed = PasswordHash::new(ph_str)?;
    Argon2::default()
        .verify_password(passphrase.as_bytes(), &parsed)
        .map_err(|_| KeywrapError::Crypto)?;

    // derive AES key again
    let mut hasher = Sha256::new();
    hasher.update(passphrase.as_bytes());
    hasher.update(salt_str.as_bytes());
    let key_bytes = hasher.finalize();
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let seed = cipher
        .decrypt(GenericArray::from_slice(nonce), ciphertext)
        .map_err(|_| KeywrapError::Crypto)?;
    if seed.len() != 32 {
        return Err(KeywrapError::Format);
    }
    // reconstruct signing key from seed
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed.try_into().unwrap());
    let pk_b64 = B64.encode(sk.verifying_key().to_bytes());
    Ok((sk, pk_b64))
}
