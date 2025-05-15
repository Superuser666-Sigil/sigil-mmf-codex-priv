use crate::loa::LOA;
use serde::{Deserialize, Serialize};
use chrono::{Utc, DateTime};

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SigilVerdict {
    Allow,
    Deny,
    Quarantine,
    Escalate,
}

/// Canonical entry in the Sigil Trust Knowledge Graph
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TrustedKnowledgeEntry {
    pub id: String,
    pub loa_required: LOA,
    pub verdict: SigilVerdict,
    pub category: String,
    pub content: String,
    pub created_at: DateTime<Utc>,
    pub sealed_by: Option<String>,
}

impl TrustedKnowledgeEntry {
    /// Ensure structural validity
    pub fn is_valid(&self) -> bool {
        !self.id.is_empty()
            && !self.category.is_empty()
            && !self.content.is_empty()
    }

    /// LOA access check
    pub fn access_verdict(&self, loa: &LOA) -> SigilVerdict {
        if loa >= &self.loa_required {
            SigilVerdict::Allow
        } else {
            self.verdict.clone()
        }
    }

    /// Readable summary
    pub fn summary(&self) -> String {
        format!(
            "[{}] LOA::{:?} → {:?} ({})",
            self.id, self.loa_required, self.verdict, self.category
        )
    }

    /// Check if matches a category (case-insensitive)
    pub fn is_category(&self, category: &str) -> bool {
        self.category.eq_ignore_ascii_case(category)
    }

    /// Check if verdict matches
    pub fn is_verdict(&self, verdict: SigilVerdict) -> bool {
        self.verdict == verdict
    }

    /// Check if accessible under a given LOA
    pub fn is_accessible_by(&self, loa: &LOA) -> bool {
        loa >= &self.loa_required
    }
}

/// Batch filters (intermediate level, runtime-friendly)
pub fn filter_by_category<'a>(
    entries: &'a [TrustedKnowledgeEntry],
    category: &str,
) -> Vec<&'a TrustedKnowledgeEntry> {
    entries.iter().filter(|e| e.is_category(category)).collect()
}

pub fn filter_by_verdict<'a>(
    entries: &'a [TrustedKnowledgeEntry],
    verdict: SigilVerdict,
) -> Vec<&'a TrustedKnowledgeEntry> {
    entries.iter().filter(|e| e.is_verdict(verdict)).collect()
}

pub fn filter_accessible<'a>(
    entries: &'a [TrustedKnowledgeEntry],
    loa: &LOA,
) -> Vec<&'a TrustedKnowledgeEntry> {
    entries.iter().filter(|e| e.is_accessible_by(loa)).collect()
}
