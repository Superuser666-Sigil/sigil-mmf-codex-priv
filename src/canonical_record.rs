use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::audit_chain::FrozenChain;
use crate::trusted_knowledge::TrustedKnowledgeEntry;
use sha2::{Sha256, Digest};
use ed25519_dalek::{SigningKey, Signer};
use rand_core::OsRng;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use hex;

/// A canonical record representation used for Codex Nexus.
///
/// Each record includes a minimal set of metadata fields that uniquely
/// identify and describe the entry regardless of downstream storage
/// technology.  The `payload` holds the domain‑specific data (for
/// example a FrozenChain, a memory block, or a RAG document).  The
/// `hash` is a hex‑encoded SHA256 hash over the canonical plaintext
/// representation of the payload (before encryption).  The `sig` and
/// `pub_key` hold the Ed25519 signature and verifying key for the
/// payload hash.  `witnesses` collects any additional signatures
/// attesting to the record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalRecord {
    pub kind: String,
    pub schema_version: u32,
    pub id: String,
    pub tenant: String,
    pub ts: DateTime<Utc>,
    pub space: String,
    pub payload: Value,
    pub links: Vec<Link>,
    pub prev: Option<String>,
    pub hash: String,
    pub sig: Option<String>,
    pub pub_key: Option<String>,
    pub witnesses: Vec<WitnessRecord>,
}

/// Simple relation between two records.  `rel` describes the
/// relationship type (e.g., "parent", "context").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Link {
    pub rel: String,
    pub id: String,
}

/// External witness signature attached to a record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessRecord {
    pub witness_id: String,
    pub signature: String,
    pub timestamp: DateTime<Utc>,
    pub authority: String,
}

impl CanonicalRecord {
    /// Construct a canonical record from a FrozenChain.  The caller
    /// provides the tenant and space (e.g., "user" vs "system").  The
    /// `prev` argument links the new record to the previous version
    /// (if any).
    pub fn from_frozen_chain(
        chain: &FrozenChain,
        tenant: &str,
        space: &str,
        prev: Option<&str>,
    ) -> Result<Self, String> {
        // Serialize the FrozenChain as JSON for the payload.  Any
        // serialization error will propagate back to the caller.
        let payload = serde_json::to_value(chain)
            .map_err(|e| format!("Failed to serialize FrozenChain: {e}"))?;

        // Map witnesses from the FrozenChain type to CanonicalRecord.
        let witnesses: Vec<WitnessRecord> = chain
            .witnesses
            .iter()
            .map(|w| WitnessRecord {
                witness_id: w.witness_id.clone(),
                signature: w.signature.clone(),
                timestamp: w.timestamp,
                authority: w.authority.clone(),
            })
            .collect();

        // Build links.  Parent chains are represented as a link of
        // relation type "parent".
        let links: Vec<Link> = chain
            .parent_chain_ids
            .iter()
            .map(|p| Link {
                rel: "parent".to_string(),
                id: p.clone(),
            })
            .collect();

        Ok(CanonicalRecord {
            kind: "frozen_chain".to_string(),
            schema_version: 1,
            id: chain.chain_id.clone(),
            tenant: tenant.to_string(),
            ts: chain.frozen_at,
            space: space.to_string(),
            payload,
            links,
            prev: prev.map(String::from),
            hash: chain.content_hash.clone(),
            sig: chain.signature.clone(),
            pub_key: chain.public_key.clone(),
            witnesses,
        })
    }

    /// Produce a canonical JSON string for this record.
    /// This uses serde_json to serialize the record with sorted keys to ensure
    /// deterministic ordering. If serialization fails, an error is returned.
    pub fn to_canonical_json(&self) -> Result<String, String> {
        // Convert to a serde_json::Value and sort the keys.
        let value = serde_json::to_value(self)
            .map_err(|e| format!("Failed to serialize CanonicalRecord: {e}"))?;

        // Sort the map keys recursively.  For canonicalization we
        // recursively sort all object keys; arrays and other types
        // remain in their original order.
        fn sort_json(value: &mut Value) {
            match value {
                Value::Object(map) => {
                    let mut entries: Vec<(String, Value)> = map.into_iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                    entries.sort_by(|a, b| a.0.cmp(&b.0));
                    for (k, mut v) in entries {
                        sort_json(&mut v);
                        map.insert(k, v);
                    }
                }
                Value::Array(arr) => {
                    for v in arr.iter_mut() {
                        sort_json(v);
                    }
                }
                _ => {}
            }
        }

        let mut sorted_value = value;
        sort_json(&mut sorted_value);
        serde_json::to_string(&sorted_value)
            .map_err(|e| format!("Failed to serialize canonical JSON: {e}"))
    }

    /// Construct a canonical record from a TrustedKnowledgeEntry.  This helper
    /// serializes the entry into a JSON payload, assigns basic metadata
    /// (kind = entry.category, id = entry.id), and signs the canonical
    /// representation using a newly generated Ed25519 key.  The caller
    /// must provide the tenant and space strings to record the origin of
    /// this data.  The schema_version can be chosen by the caller to
    /// enable future migrations.
    pub fn from_trusted_entry(
        entry: &TrustedKnowledgeEntry,
        tenant: &str,
        space: &str,
        schema_version: u32,
    ) -> Result<Self, String> {
        // Convert the TrustedKnowledgeEntry to a JSON value.  Any
        // serialization error is propagated back to the caller.
        let payload = serde_json::to_value(entry)
            .map_err(|e| format!("Failed to serialize TrustedKnowledgeEntry: {e}"))?;

        // Build a provisional record (without hash/signature) so we can
        // canonicalize it for hashing and signing.  Use empty links
        // and witnesses, and None prev for now.
        let mut record = CanonicalRecord {
            kind: entry.category.clone(),
            schema_version,
            id: entry.id.clone(),
            tenant: tenant.to_string(),
            ts: chrono::Utc::now(),
            space: space.to_string(),
            payload,
            links: Vec::new(),
            prev: None,
            hash: String::new(),
            sig: None,
            pub_key: None,
            witnesses: Vec::new(),
        };

        // Canonicalize the JSON for hashing.  This uses the same
        // canonicalization routine as to_canonical_json, sorting keys
        // consistently.  If canonicalization fails, return an error.
        let canon_json = record.to_canonical_json()?;

        // Compute SHA256 hash of the canonical JSON string.
        let mut hasher = Sha256::new();
        hasher.update(canon_json.as_bytes());
        let digest = hasher.finalize();
        let hash_hex = hex::encode(digest);

        // Generate a new signing key for this record.  In a real
        // deployment this key would be loaded from secure storage.
        let signing_key = SigningKey::generate(&mut OsRng);
        let signature = signing_key.sign(canon_json.as_bytes());
        let sig_b64 = B64.encode(&signature.to_bytes());
        let pub_b64 = B64.encode(&signing_key.verifying_key().to_bytes());

        // Populate the hash, signature and public key on the record.
        record.hash = hash_hex;
        record.sig = Some(sig_b64);
        record.pub_key = Some(pub_b64);

        Ok(record)
    }
}