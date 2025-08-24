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

impl LOA {
    /// Check if this LOA level can perform a specific action
    pub fn can_perform_action(&self, action: &str, _resource: &str) -> bool {
        match self {
            LOA::Root => true,
            LOA::Mentor => matches!(action, "read" | "write" | "audit" | "validate" | "train" | "export"),
            LOA::Operator => matches!(action, "read" | "write" | "audit" | "validate"),
            LOA::Observer => matches!(action, "read" | "audit" | "validate"),
            LOA::Guest => matches!(action, "read"),
        }
    }
    
    /// Check if this LOA level can access a specific resource
    pub fn can_access_resource(&self, resource: &str) -> bool {
        match self {
            LOA::Root => true,
            LOA::Mentor => !resource.contains("system") && !resource.contains("elevation"),
            LOA::Operator => !resource.contains("system") && !resource.contains("admin") && !resource.contains("elevation"),
            LOA::Observer => !resource.contains("system") && !resource.contains("admin") && !resource.contains("write") && !resource.contains("elevation"),
            LOA::Guest => resource.contains("public") || resource.contains("readonly"),
        }
    }
    
    /// Get the minimum LOA required for an action
    pub fn required_for_action(action: &str) -> Option<LOA> {
        match action {
            "read" => Some(LOA::Guest),
            "audit" => Some(LOA::Observer),
            "validate" => Some(LOA::Observer),
            "write" => Some(LOA::Operator),
            "train" => Some(LOA::Mentor),
            "export" => Some(LOA::Mentor),
            "elevate" => Some(LOA::Mentor),
            "system" => Some(LOA::Root),
            _ => None,
        }
    }
    
    /// Check if this LOA can elevate to target LOA
    pub fn can_elevate_to(&self, target: &LOA) -> bool {
        matches!(
            (self, target),
            (LOA::Root, _) | (LOA::Mentor, LOA::Root) | (LOA::Operator, LOA::Mentor | LOA::Root) | (LOA::Observer, LOA::Operator | LOA::Mentor | LOA::Root) | (LOA::Guest, LOA::Observer | LOA::Operator | LOA::Mentor | LOA::Root)
        )
    }
    
    /// Get the next LOA level in the hierarchy
    pub fn next_level(&self) -> Option<LOA> {
        match self {
            LOA::Guest => Some(LOA::Observer),
            LOA::Observer => Some(LOA::Operator),
            LOA::Operator => Some(LOA::Mentor),
            LOA::Mentor => Some(LOA::Root),
            LOA::Root => None,
        }
    }
    
    /// Get the previous LOA level in the hierarchy
    pub fn previous_level(&self) -> Option<LOA> {
        match self {
            LOA::Guest => None,
            LOA::Observer => Some(LOA::Guest),
            LOA::Operator => Some(LOA::Observer),
            LOA::Mentor => Some(LOA::Operator),
            LOA::Root => Some(LOA::Mentor),
        }
    }
}
