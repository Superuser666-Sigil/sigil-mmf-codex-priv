use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LOA {
    Guest,
    Observer,
    Operator,
    Mentor,
    Root,
}

// Type alias for backward compatibility
pub type LoaLevel = LOA;

impl FromStr for LOA {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "guest" => Ok(LOA::Guest),
            "observer" => Ok(LOA::Observer),
            "operator" => Ok(LOA::Operator),
            "mentor" => Ok(LOA::Mentor),
            "root" => Ok(LOA::Root),
            _ => Err(format!("Unknown LOA level: {s}")),
        }
    }
}

impl From<&str> for LOA {
    fn from(s: &str) -> Self {
        s.parse().unwrap_or(LOA::Guest)
    }
}

impl fmt::Display for LOA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// Missing functions that are referenced in other modules
pub fn enforce(required: LOA, user: LOA) -> Result<(), String> {
    if user >= required {
        Ok(())
    } else {
        Err(format!(
            "Insufficient LOA: required {required:?}, got {user:?}"
        ))
    }
}

pub fn can_read_canon(user_loa: &LOA) -> bool {
    matches!(
        user_loa,
        LOA::Observer | LOA::Operator | LOA::Mentor | LOA::Root
    )
}

pub fn can_write_canon(user_loa: &LOA) -> bool {
    matches!(user_loa, LOA::Operator | LOA::Mentor | LOA::Root)
}
