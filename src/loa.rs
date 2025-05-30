use std::str::FromStr;
use std::fmt;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LOA {
    Guest,
    Ephemeral,
    Limited,
    Trusted,
    Root,
}

impl FromStr for LOA {
    type Err = ();

    fn from_str(input: &str) -> Result<LOA, Self::Err> {
        match input.to_lowercase().as_str() {
            "guest" => Ok(LOA::Guest),
            "ephemeral" => Ok(LOA::Ephemeral),
            "limited" => Ok(LOA::Limited),
            "trusted" => Ok(LOA::Trusted),
            "root" => Ok(LOA::Root),
            _ => Err(()),
        }
    }
}

impl fmt::Display for LOA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
