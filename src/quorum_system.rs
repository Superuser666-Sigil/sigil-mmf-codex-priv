use crate::errors::SigilResult;
use crate::witness_registry::WitnessRegistry;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

/// System proposal for canon changes requiring quorum
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemProposal {
    pub id: String,
    pub entry: String,
    pub content: String,
    pub content_hash: String,
    pub required_k: usize,
    pub signers: Vec<WitnessSignature>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Witness signature for a system proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessSignature {
    pub witness_id: String,
    pub signature: String,
    pub signed_at: DateTime<Utc>,
}

impl SystemProposal {
    pub fn new(entry: String, content: String, required_k: usize) -> Self {
        let id = Uuid::new_v4().to_string();
        let content_hash = Self::calculate_content_hash(&entry, &content);
        let created_at = Utc::now();
        let expires_at = created_at + chrono::Duration::hours(24); // 24 hour expiry

        Self {
            id,
            entry,
            content,
            content_hash,
            required_k,
            signers: Vec::new(),
            created_at,
            expires_at,
        }
    }

    fn calculate_content_hash(entry: &str, content: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(format!("{}:{}", entry, content).as_bytes());
        format!("{:x}", hasher.finalize())
    }

    pub fn add_signature(&mut self, witness_id: String, signature: String) -> SigilResult<()> {
        // Check if witness already signed
        if self.signers.iter().any(|s| s.witness_id == witness_id) {
            return Err(crate::errors::SigilError::invalid_input(
                "add_signature",
                &format!("Witness {} already signed this proposal", witness_id),
            ));
        }

        // Validate signature format (basic check)
        if signature.is_empty() {
            return Err(crate::errors::SigilError::invalid_input(
                "add_signature",
                "Signature cannot be empty",
            ));
        }

        let witness_sig = WitnessSignature {
            witness_id,
            signature,
            signed_at: Utc::now(),
        };

        self.signers.push(witness_sig);
        Ok(())
    }

    pub fn has_quorum(&self) -> bool {
        self.signers.len() >= self.required_k
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn get_signature_count(&self) -> usize {
        self.signers.len()
    }

    pub fn get_remaining_signatures_needed(&self) -> usize {
        if self.required_k > self.signers.len() {
            self.required_k - self.signers.len()
        } else {
            0
        }
    }
}

/// Quorum system for managing system proposals
pub struct QuorumSystem {
    proposals: HashMap<String, SystemProposal>,
    witness_registry: Arc<WitnessRegistry>,
}

impl QuorumSystem {
    pub fn new(witness_registry: Arc<WitnessRegistry>) -> Self {
        Self {
            proposals: HashMap::new(),
            witness_registry,
        }
    }

    pub fn create_proposal(
        &mut self,
        entry: String,
        content: String,
        required_k: usize,
    ) -> SigilResult<String> {
        let proposal = SystemProposal::new(entry, content, required_k);
        let id = proposal.id.clone();
        self.proposals.insert(id.clone(), proposal);
        Ok(id)
    }

    pub fn get_proposal(&self, id: &str) -> Option<&SystemProposal> {
        self.proposals.get(id)
    }

    pub fn add_signature(
        &mut self,
        proposal_id: &str,
        witness_id: String,
        signature: String,
    ) -> SigilResult<()> {
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or_else(|| crate::errors::SigilError::not_found("proposal", proposal_id))?;

        if proposal.is_expired() {
            return Err(crate::errors::SigilError::invalid_input(
                "add_signature",
                "Proposal has expired",
            ));
        }

        // Validate the witness signature against the proposal content hash
        let message = proposal.content_hash.as_bytes();
        let is_valid =
            self.witness_registry
                .validate_witness_signature(&witness_id, message, &signature)?;

        if !is_valid {
            return Err(crate::errors::SigilError::crypto_error(format!(
                "Invalid signature from witness {}",
                witness_id
            )));
        }

        proposal.add_signature(witness_id, signature)
    }

    pub fn commit_proposal(&mut self, proposal_id: &str) -> SigilResult<SystemProposal> {
        let proposal = self
            .proposals
            .get(proposal_id)
            .ok_or_else(|| crate::errors::SigilError::not_found("proposal", proposal_id))?;

        if proposal.is_expired() {
            return Err(crate::errors::SigilError::invalid_input(
                "commit_proposal",
                "Proposal has expired",
            ));
        }

        if !proposal.has_quorum() {
            return Err(crate::errors::SigilError::Internal {
                message: format!(
                    "Proposal requires {} signatures, got {}",
                    proposal.required_k,
                    proposal.signers.len()
                ),
            });
        }

        // Remove the proposal from pending list
        let committed_proposal = self
            .proposals
            .remove(proposal_id)
            .ok_or_else(|| crate::errors::SigilError::not_found("proposal", proposal_id))?;

        Ok(committed_proposal)
    }

    pub fn list_pending_proposals(&self) -> Vec<&SystemProposal> {
        self.proposals
            .values()
            .filter(|p| !p.is_expired())
            .collect()
    }

    pub fn cleanup_expired_proposals(&mut self) -> usize {
        let expired_ids: Vec<String> = self
            .proposals
            .iter()
            .filter(|(_, proposal)| proposal.is_expired())
            .map(|(id, _)| id.clone())
            .collect();

        let count = expired_ids.len();
        for id in expired_ids {
            self.proposals.remove(&id);
        }
        count
    }

    pub fn get_proposal_status(&self, proposal_id: &str) -> Option<ProposalStatus> {
        self.proposals
            .get(proposal_id)
            .map(|proposal| ProposalStatus {
                id: proposal.id.clone(),
                entry: proposal.entry.clone(),
                required_k: proposal.required_k,
                current_signatures: proposal.signers.len(),
                has_quorum: proposal.has_quorum(),
                is_expired: proposal.is_expired(),
                expires_at: proposal.expires_at,
            })
    }
}

/// Status information for a proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalStatus {
    pub id: String,
    pub entry: String,
    pub required_k: usize,
    pub current_signatures: usize,
    pub has_quorum: bool,
    pub is_expired: bool,
    pub expires_at: DateTime<Utc>,
}

// Note: No Default implementation - QuorumSystem requires WitnessRegistry

#[cfg(test)]
mod tests {
    use super::*;

    use crate::canon_store_sled_encrypted::CanonStoreSled as EncryptedCanonStoreSled;
    use crate::keys::KeyManager;
    use crate::witness_registry::WitnessRegistry;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use tempfile::TempDir;

    fn create_test_quorum_system() -> (QuorumSystem, TempDir, SigningKey, String) {
        let temp_dir = TempDir::new().unwrap();
        let store_path = temp_dir.path().join("test_canon.db");
        let encryption_key = KeyManager::get_encryption_key().unwrap();
        let canon_store = Arc::new(std::sync::Mutex::new(
            EncryptedCanonStoreSled::new(store_path.to_str().unwrap(), &encryption_key).unwrap(),
        ));

        // Create a real Ed25519 signing key for testing
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key_b64 =
            base64::engine::general_purpose::STANDARD.encode(verifying_key.as_bytes());

        // Create witness registry and add the test witness
        let witness_registry = Arc::new(WitnessRegistry::new(canon_store.clone()).unwrap());
        let witness_id = "test_witness_1".to_string();
        witness_registry
            .add_witness(
                witness_id.clone(),
                public_key_b64,
                "test_authority".to_string(),
                "Test witness for quorum tests".to_string(),
                &crate::loa::LOA::Root,
            )
            .unwrap();

        let quorum_system = QuorumSystem::new(witness_registry);
        (quorum_system, temp_dir, signing_key, witness_id)
    }

    #[test]
    fn test_proposal_creation() {
        let (mut quorum, _temp_dir, _signing_key, _witness_id) = create_test_quorum_system();

        let proposal_id = quorum
            .create_proposal("test_entry".to_string(), "test_content".to_string(), 3)
            .unwrap();

        assert!(quorum.get_proposal(&proposal_id).is_some());
        let proposal = quorum.get_proposal(&proposal_id).unwrap();
        assert_eq!(proposal.required_k, 3);
        assert_eq!(proposal.signers.len(), 0);
        assert!(!proposal.has_quorum());
    }

    #[test]
    fn test_quorum_validation_with_real_signatures() {
        let (mut quorum, _temp_dir, signing_key, witness_id) = create_test_quorum_system();

        // Create a proposal
        let proposal_id = quorum
            .create_proposal(
                "test_entry".to_string(),
                "test_content".to_string(),
                1, // Only need 1 signature for this test
            )
            .unwrap();

        // Get the proposal to sign its content hash
        let proposal = quorum.get_proposal(&proposal_id).unwrap();
        let message = proposal.content_hash.as_bytes();

        // Create a real Ed25519 signature
        let signature = signing_key.sign(message);
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

        // Add the signature
        quorum
            .add_signature(&proposal_id, witness_id, signature_b64)
            .unwrap();

        // Verify quorum is achieved
        let updated_proposal = quorum.get_proposal(&proposal_id).unwrap();
        assert!(updated_proposal.has_quorum());
        assert_eq!(updated_proposal.signers.len(), 1);
    }

    #[test]
    fn test_invalid_signature_rejection() {
        let (mut quorum, _temp_dir, _signing_key, witness_id) = create_test_quorum_system();

        // Create a proposal
        let proposal_id = quorum
            .create_proposal("test_entry".to_string(), "test_content".to_string(), 1)
            .unwrap();

        // Try to add an invalid signature
        let invalid_signature = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 64]); // Invalid signature bytes

        let result = quorum.add_signature(&proposal_id, witness_id, invalid_signature);
        assert!(result.is_err());

        // Verify no signature was added
        let proposal = quorum.get_proposal(&proposal_id).unwrap();
        assert_eq!(proposal.signers.len(), 0);
        assert!(!proposal.has_quorum());
    }

    #[test]
    fn test_duplicate_signature_prevention() {
        let (mut quorum, _temp_dir, signing_key, witness_id) = create_test_quorum_system();

        // Create a proposal
        let proposal_id = quorum
            .create_proposal("test_entry".to_string(), "test_content".to_string(), 2)
            .unwrap();

        // Get the proposal to sign its content hash
        let proposal = quorum.get_proposal(&proposal_id).unwrap();
        let message = proposal.content_hash.as_bytes();

        // Create a real Ed25519 signature
        let signature = signing_key.sign(message);
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

        // Add the signature once
        quorum
            .add_signature(&proposal_id, witness_id.clone(), signature_b64.clone())
            .unwrap();

        // Try to add the same witness signature again
        let result = quorum.add_signature(&proposal_id, witness_id, signature_b64);
        assert!(result.is_err());

        // Verify only one signature exists
        let proposal = quorum.get_proposal(&proposal_id).unwrap();
        assert_eq!(proposal.signers.len(), 1);
    }
}
