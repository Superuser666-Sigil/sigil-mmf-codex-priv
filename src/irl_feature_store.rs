// Canon-Compliant irl_feature_store.rs
// Purpose: Store and export trace-linked IRL feature vectors with audit alignment

use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use std::collections::VecDeque;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeatureRecord {
    pub trace_id: String,
    pub features: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Default)]
pub struct FeatureStore {
    pub records: VecDeque<FeatureRecord>,
    pub max_entries: usize,
}

impl FeatureStore {
    pub fn new(max_entries: usize) -> Self {
        Self {
            records: VecDeque::with_capacity(max_entries),
            max_entries,
        }
    }

    pub fn add_features(&mut self, trace_id: &str, features: Vec<String>) {
        if self.records.len() == self.max_entries {
            self.records.pop_front(); // discard oldest
        }

        self.records.push_back(FeatureRecord {
            trace_id: trace_id.into(),
            features,
            timestamp: Utc::now(),
        });
    }

    pub fn export_all(&self) -> Vec<FeatureRecord> {
        self.records.iter().cloned().collect()
    }

    pub fn clear(&mut self) {
        self.records.clear();
    }
}
