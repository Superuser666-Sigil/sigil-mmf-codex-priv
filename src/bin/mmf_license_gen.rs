use clap::Parser;
use serde::Serialize;
use sha2::{Sha256, Digest};
use ed25519_dalek::Signer;
use base64::Engine as _; 
use base64::engine::general_purpose::STANDARD as b64;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use std::{fs, path::PathBuf};

use mmf_sigil::crypto::KeyStore;

/// Canonicalize deterministically: if your repo has RFC 8785, replace this with it.
fn canonical_json_bytes<T: Serialize>(v: &T) -> Vec<u8> {
    // deterministic via serde_json + map ordering by using BTreeMap via intermediate Value
    let val = serde_json::to_value(v).expect("ser");
    fn sort(v: &serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(m) => {
                let mut b = std::collections::BTreeMap::new();
                for (k, vv) in m { 
                    b.insert(k.clone(), sort(vv)); 
                }
                serde_json::Value::Object(b.into_iter().collect())
            }
            serde_json::Value::Array(a) => serde_json::Value::Array(a.iter().map(sort).collect()),
            _ => v.clone()
        }
    }
    serde_json::to_vec(&sort(&val)).unwrap()
}

#[derive(Parser)]
struct Args {
    /// owner id (email or uuid)
    #[arg(long)]
    owner_id: String,
    /// owner name
    #[arg(long)]
    owner_name: String,
    /// loa: guest|observer|operator|mentor|root
    #[arg(long)]
    loa: String,
    /// runtime id binding
    #[arg(long)]
    runtime_id: String,
    /// canon fingerprint binding
    #[arg(long)]
    canon_fingerprint: String,
    /// expiration RFC3339
    #[arg(long)]
    expires_at: String,
    /// output file
    #[arg(long)]
    out: PathBuf,
    /// key dir (default /var/lib/mmf/keys)
    #[arg(long, default_value="/var/lib/mmf/keys")]
    key_dir: PathBuf,
    /// passphrase to decrypt root license key (from env if not provided)
    #[arg(long)]
    passphrase: Option<String>,
}

#[derive(Serialize)]
struct License<'a> {
    owner: Owner<'a>,
    loa: &'a str,
    #[serde(rename = "issuedAt")]
    issued_at: String,
    #[serde(rename = "expiresAt")]
    expires_at: &'a str,
    bindings: Bindings<'a>,
}

#[derive(Serialize)]
struct Owner<'a> { 
    id: &'a str, 
    name: &'a str 
}

#[derive(Serialize)]
struct Bindings<'a> { 
    #[serde(rename = "runtimeId")]
    runtime_id: &'a str, 
    #[serde(rename = "canonFingerprint")]
    canon_fingerprint: &'a str 
}

#[derive(Serialize)]
struct Sealed<'a> {
    license: License<'a>,
    seal: Seal<'a>,
}

#[derive(Serialize)]
struct Seal<'a> {
    alg: &'a str,
    sig: String,
    pubkey: String,
    #[serde(rename = "contentHash")]
    content_hash: String,
}

fn main() -> anyhow::Result<()> {
    let a = Args::parse();
    let pass = a.passphrase.or_else(|| std::env::var("MMF_LICENSE_KDF_PASSPHRASE").ok())
        .expect("Provide --passphrase or set MMF_LICENSE_KDF_PASSPHRASE");

    // 1) load or create root license signing key
    let ks = KeyStore::new(&a.key_dir);
    let (sk, pk_b64) = ks.load_or_create_ed25519("root_license.ed25519.enc", &pass)
        .expect("failed to load/create root license key");

    // 2) build license
    let now = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let lic = License {
        owner: Owner { id: &a.owner_id, name: &a.owner_name },
        loa: &a.loa,
        issued_at: now,
        expires_at: &a.expires_at,
        bindings: Bindings { 
            runtime_id: &a.runtime_id, 
            canon_fingerprint: &a.canon_fingerprint 
        },
    };

    // 3) canonical bytes + hash
    let cbytes = canonical_json_bytes(&lic);
    let hash = Sha256::digest(&cbytes);
    let hash_b64 = b64.encode(hash);

    // 4) sign
    let sig = sk.sign(&cbytes);
    let sig_b64 = b64.encode(sig.to_bytes());

    // 5) package & write TOML
    let sealed = Sealed {
        license: lic,
        seal: Seal { 
            alg: "ed25519", 
            sig: sig_b64, 
            pubkey: pk_b64, 
            content_hash: hash_b64 
        },
    };
    let toml_str = toml::to_string_pretty(&sealed)?;
    fs::write(&a.out, toml_str)?;
    eprintln!("Wrote license: {}", a.out.display());
    Ok(())
}
