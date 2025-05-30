use crate::audit_store::write_chain;
use crate::trust_registry::{register_scope, release_scope};
use std::str::FromStr;

pub fn display_status(ctx: &crate::session_context::SessionContext) {
    println!("[status] session active: {}", ctx.session_id);
}