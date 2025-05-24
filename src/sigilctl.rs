// Canon-Compliant sigilctl.rs
// Purpose: Display runtime trust context, session identity, and audit-aligned diagnostics

use crate::session_context::SessionContext;
use crate::audit::{AuditEvent, LogLevel};
use chrono::Utc;

pub fn print_session_diagnostics(ctx: &SessionContext) -> AuditEvent {
    let loa = ctx.loa.name();
    let ident = ctx.identity_hash();
    let time = Utc::now();
    let ephemeral = if ctx.ephemeral { "(ephemeral)" } else { "" };

    println!("╭───────────────────────────────");
    println!("│ MMF Runtime Session Context");
    println!("├───────────────────────────────");
    println!("│ Session ID   : {}", ctx.session_id);
    println!("│ User Hash    : {}", ident);
    println!("│ LOA Level    : {}", loa);
    println!("│ Ephemeral    : {}", ctx.ephemeral);
    println!("│ Issued At    : {}", time);
    println!("╰───────────────────────────────");

    AuditEvent::new(
        &ident,
        "sigilctl_session_diagnostics",
        &ctx.session_id,
        "sigilctl.rs",
    )
    .with_context(format!("Session running as {:?}{}", ctx.loa, ephemeral))
    .with_severity(LogLevel::Info)
}

pub fn print_license_summary(ctx: &SessionContext) {
    if let Some(license) = &ctx.license {
        println!("╭────────── LICENSE BOUND ──────────");
        println!("│ Owner      : {}", license.owner.name);
        println!("│ Mnemonic   : {}", license.owner.mnemonic);
        println!("│ LOA        : {}", license.loa.name());
        println!("│ Runtime ID : {}", license.bindings.runtime_id);
        println!("│ Sealed     : {}", license.trust.sealed);
        println!("│ Scope      : {:?}", license.scope);
        println!("│ Expires At : {}", license.expires_at);
        println!("╰───────────────────────────────────");
    } else {
        println!("❌ No active license bound to this session.");
    }
}

pub fn print_config_summary(ctx: &SessionContext) {
    println!("╭───────── CONFIG SNAPSHOT ─────────");
    println!("│ Data Dir       : {}", ctx.config.data_dir);
    println!("│ Audit Log Path : {}", ctx.config.audit_log_path);
    println!("│ Encryption Key : {}", if ctx.config.encryption_key_b64.is_some() { "present" } else { "absent" });
    println!("│ Allow Operator : {}", ctx.config.trust.allow_operator_canon_write);
    println!("╰───────────────────────────────────");
}
