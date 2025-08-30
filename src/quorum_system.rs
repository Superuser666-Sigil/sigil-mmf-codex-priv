use crate::errors::SigilResult;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};

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
                &format!("Witness {} already signed this proposal", witness_id)
            ));
        }
        
        // Validate signature format (basic check)
        if signature.is_empty() {
            return Err(crate::errors::SigilError::invalid_input(
                "add_signature",
                "Signature cannot be empty"
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
}

impl QuorumSystem {
    pub fn new() -> Self {
        Self {
            proposals: HashMap::new(),
        }
    }
    
    pub fn create_proposal(&mut self, entry: String, content: String, required_k: usize) -> SigilResult<String> {
        let proposal = SystemProposal::new(entry, content, required_k);
        let id = proposal.id.clone();
        self.proposals.insert(id.clone(), proposal);
        Ok(id)
    }
    
    pub fn get_proposal(&self, id: &str) -> Option<&SystemProposal> {
        self.proposals.get(id)
    }
    
    pub fn add_signature(&mut self, proposal_id: &str, witness_id: String, signature: String) -> SigilResult<()> {
        let proposal = self.proposals.get_mut(proposal_id)
            .ok_or_else(|| crate::errors::SigilError::not_found("proposal", proposal_id))?;
        
        if proposal.is_expired() {
            return Err(crate::errors::SigilError::invalid_input(
                "add_signature",
                "Proposal has expired"
            ));
        }
        
        proposal.add_signature(witness_id, signature)
    }
    
    pub fn commit_proposal(&mut self, proposal_id: &str) -> SigilResult<SystemProposal> {
        let proposal = self.proposals.get(proposal_id)
            .ok_or_else(|| crate::errors::SigilError::not_found("proposal", proposal_id))?;
        
        if proposal.is_expired() {
            return Err(crate::errors::SigilError::invalid_input(
                "commit_proposal",
                "Proposal has expired"
            ));
        }
        
        if !proposal.has_quorum() {
                        return Err(crate::errors::SigilError::Internal {
                message: format!("Proposal requires {} signatures, got {}",
                        proposal.required_k, proposal.signers.len())
            });
        }
        
        // Remove the proposal from pending list
        let committed_proposal = self.proposals.remove(proposal_id)
            .ok_or_else(|| crate::errors::SigilError::not_found("proposal", proposal_id))?;
        
        Ok(committed_proposal)
    }
    
    pub fn list_pending_proposals(&self) -> Vec<&SystemProposal> {
        self.proposals.values()
            .filter(|p| !p.is_expired())
            .collect()
    }
    
    pub fn cleanup_expired_proposals(&mut self) -> usize {
        let expired_ids: Vec<String> = self.proposals.iter()
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
        self.proposals.get(proposal_id).map(|proposal| ProposalStatus {
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

impl Default for QuorumSystem {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_proposal_creation() {
        let mut quorum = QuorumSystem::new();
        let proposal_id = quorum.create_proposal(
            "test_entry".to_string(),
            "test_content".to_string(),
            3
        ).unwrap();
        
        assert!(quorum.get_proposal(&proposal_id).is_some());
    }
    
    #[test]
    fn test_quorum_validation() {
        let mut proposal = SystemProposal::new(
            "test_entry".to_string(),
            "test_content".to_string(),
            2
        );
        
        assert!(!proposal.has_quorum());
        
        proposal.add_signature("witness1".to_string(), "sig1".to_string()).unwrap();
        assert!(!proposal.has_quorum());
        
        proposal.add_signature("witness2".to_string(), "sig2".to_string()).unwrap();
        assert!(proposal.has_quorum());
    }
    
    #[test]
    fn test_duplicate_signature_prevention() {
        let mut proposal = SystemProposal::new(
            "test_entry".to_string(),
            "test_content".to_string(),
            2
        );
        
        proposal.add_signature("witness1".to_string(), "sig1".to_string()).unwrap();
        
        // Try to add the same witness again
        let result = proposal.add_signature("witness1".to_string(), "sig2".to_string());
        assert!(result.is_err());
    }
}

