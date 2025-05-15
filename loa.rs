// Canon-Compliant loa.rs
// Purpose: Define Levels of Access (LOA) and trust enforcement roles in MMF + Sigil

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LOA {
    Observer,
    Operator,
    Root,
}

impl LOA {
    pub fn name(&self) -> &'static str {
        match self {
            LOA::Observer => "Observer",
            LOA::Operator => "Operator",
            LOA::Root => "Root",
        }
    }

    pub fn can_elevate(&self) -> bool {
        matches!(self, LOA::Observer | LOA::Operator)
    }

    pub fn can_mutate_canon(&self, allow_operator: bool) -> bool {
        match self {
            LOA::Root => true,
            LOA::Operator => allow_operator,
            _ => false,
        }
    }

    pub fn can_write_config(&self) -> bool {
        matches!(self, LOA::Root)
    }

    pub fn can_register_module(&self) -> bool {
        matches!(self, LOA::Root | LOA::Operator)
    }

    pub fn can_view_audit(&self) -> bool {
        true // all levels may inspect audit logs
    }
}

/// Utility functions to avoid repeating pattern matching logic
pub fn can_read_canon(loa: &LOA) -> bool {
    matches!(loa, LOA::Operator | LOA::Root)
}

pub fn can_write_canon(loa: &LOA, allow_operator_write: bool) -> bool {
    match loa {
        LOA::Root => true,
        LOA::Operator => allow_operator_write,
        _ => false,
    }
}
