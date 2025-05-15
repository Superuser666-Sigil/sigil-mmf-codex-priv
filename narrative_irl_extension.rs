// Canon-Compliant narrative_irl_extension.rs
// Purpose: Modify IRL trust scoring based on character narrative context and ethical motives

use chrono::{Utc};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NarrativeContext {
    pub actor_id: String,
    pub motive: NarrativeMotive,
    pub tone: NarrativeTone,
    pub arc_stage: NarrativeArc,
    pub reason_summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NarrativeMotive {
    SelfPreservation,
    Altruism,
    Revenge,
    Growth,
    Loyalty,
    Survival,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NarrativeTone {
    Calm,
    Angry,
    Fearful,
    Grieving,
    Reflective,
    Driven,
    Detached,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NarrativeArc {
    Origin,
    Midpoint,
    Climax,
    Resolution,
    Reversal,
    Unknown,
}

/// Applies narrative modifiers to an existing IRL trust score.
/// Intended to subtly reinforce or temper trust outcomes based on context.
pub fn apply_narrative_modifier(base_score: f32, context: &NarrativeContext) -> f32 {
    let mut modifier = 0.0;

    modifier += match context.motive {
        NarrativeMotive::Altruism => 0.1,
        NarrativeMotive::Revenge => -0.1,
        NarrativeMotive::Growth => 0.05,
        NarrativeMotive::SelfPreservation => 0.0,
        NarrativeMotive::Loyalty => 0.07,
        NarrativeMotive::Survival => 0.0,
        NarrativeMotive::Unknown => -0.05,
    };

    modifier += match context.tone {
        NarrativeTone::Grieving => -0.05,
        NarrativeTone::Angry => -0.1,
        NarrativeTone::Reflective => 0.1,
        NarrativeTone::Calm => 0.05,
        NarrativeTone::Driven => 0.02,
        NarrativeTone::Fearful => -0.05,
        NarrativeTone::Detached => -0.02,
    };

    modifier += match context.arc_stage {
        NarrativeArc::Origin => 0.0,
        NarrativeArc::Midpoint => 0.05,
        NarrativeArc::Climax => -0.1,
        NarrativeArc::Resolution => 0.1,
        NarrativeArc::Reversal => -0.05,
        NarrativeArc::Unknown => 0.0,
    };

    (base_score + modifier).clamp(0.0, 1.0)
}
