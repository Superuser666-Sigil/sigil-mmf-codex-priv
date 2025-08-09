use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureVector {
    pub features: Vec<f32>,
}

impl FeatureVector {
    pub fn new(features: Vec<f32>) -> Self {
        FeatureVector { features }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardModel {
    pub model_id: String,
    pub description: Option<String>,
    pub features: Vec<String>,
    pub weights: Vec<f32>,
}

impl RewardModel {
    pub fn new(
        model_id: &str,
        description: Option<String>,
        features: Vec<String>,
        weights: Vec<f32>,
    ) -> Self {
        RewardModel {
            model_id: model_id.to_string(),
            description,
            features,
            weights,
        }
    }
}
