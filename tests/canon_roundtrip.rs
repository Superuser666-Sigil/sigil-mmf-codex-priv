//! Canon record write/load/verify round-trip test

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use mmf_sigil::{
    canon_store::CanonStore,
    canon_store_sled_encrypted::CanonStoreSled as EncryptedCanonStoreSled,
    canonical_record::CanonicalRecord,
    keys::KeyManager,
    loa::LOA,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

#[test]
fn canon_roundtrip_write_and_verify() {
    let tmp = TempDir::new().expect("tmp dir");
    let enc_key = KeyManager::dev_key_for_testing().expect("encryption key");
    let mut store = EncryptedCanonStoreSled::new(tmp.path().to_str().unwrap(), &enc_key)
        .expect("encrypted sled store");

    // Create a simple record
    let payload = serde_json::json!({"k":"v"});
    let mut record = CanonicalRecord::new_minimal_for_test("roundtrip", "system", "audit", payload);

    // Canonicalize and hash
    let canonical = record.to_canonical_json().expect("canonicalize");
    let digest = Sha256::digest(canonical.as_bytes());
    record.hash = hex::encode(digest);

    // Sign using a temporary key (reuse KeyManager's deterministic path is avoided)
    let signing = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying = signing.verifying_key();
    let sig = signing.sign(canonical.as_bytes());
    record.sig = Some(B64.encode(sig.to_bytes()));
    record.pub_key = Some(B64.encode(verifying.as_bytes()));

    // Persist
    store
        .add_record(record.clone(), &LOA::Operator, true)
        .expect("add");

    // Load and verify
    let loaded = store
        .load_record(&record.id, &LOA::Operator)
        .expect("load some");
    let canonical2 = loaded.to_canonical_json().expect("canonicalize");
    let digest2 = Sha256::digest(canonical2.as_bytes());
    assert_eq!(hex::encode(digest2), loaded.hash, "hash must match");

    let sig_bytes = B64.decode(loaded.sig.as_ref().unwrap()).unwrap();
    let pk_bytes = B64.decode(loaded.pub_key.as_ref().unwrap()).unwrap();
    let verifying = VerifyingKey::from_bytes(&pk_bytes.try_into().unwrap()).unwrap();
    let signature = Signature::from_bytes(&sig_bytes.try_into().unwrap());
    verifying
        .verify(canonical2.as_bytes(), &signature)
        .expect("verify");
}
