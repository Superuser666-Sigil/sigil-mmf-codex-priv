use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LOA {
    Observer,
    Operator,
    Mentor,
    Root,
}

impl LOA {
    pub fn name(&self) -> &'static str {
        match self {
            LOA::Observer => "Observer",
            LOA::Operator => "Operator",
            LOA::Mentor => "Mentor",
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
        LOA::Mentor => allow_operator_write,
        LOA::Root => true,
        LOA::Operator => allow_operator_write,
        _ => false,
    }
}

// Canon Access Traits
pub trait CanonReadAccess {
    fn can_read(&self) -> bool;
}

pub trait CanonWriteAccess {
    fn can_write(&self) -> bool;
}

pub trait CanonAdminAccess: CanonReadAccess + CanonWriteAccess {
    fn can_elevate(&self) -> bool;
}

impl CanonReadAccess for LOA {
    fn can_read(&self) -> bool {
        matches!(self, LOA::Mentor | LOA::Root)
    }
}

impl CanonWriteAccess for LOA {
    fn can_write(&self) -> bool {
        matches!(self, LOA::Root | LOA::Operator) // <— bonus: allow Operator write access
    }
}

impl CanonAdminAccess for LOA {
    fn can_elevate(&self) -> bool {
        matches!(self, LOA::Root)
    }
}
