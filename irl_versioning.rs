// Canon-Compliant irl_versioning.rs
// Purpose: Version control and compatibility tracking for IRL trust modules

use serde::{Serialize, Deserialize};

pub const IRL_VERSION: &str = "v1.0.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IRLVersionMetadata {
    pub version: String,
    pub compatible_since: String,
    pub verified: bool,
}

pub fn verify_version(expected: &str) -> bool {
    IRL_VERSION == expected
}

pub fn current_version_metadata() -> IRLVersionMetadata {
    IRLVersionMetadata {
        version: IRL_VERSION.into(),
        compatible_since: "v1.0.0".into(),
        verified: true,
    }
}
