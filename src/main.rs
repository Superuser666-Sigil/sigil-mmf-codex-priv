// Sigil Runtime - main.rs
// Bootstrap runner compliant with Codex Rule Zero, Canon LOA policies, and IRL trace audit

mod config;
mod config_loader;
mod license_validator;
mod session_context;
mod audit;
mod loa;

use std::process::exit;
use crate::config_loader::load_config;
use crate::license_validator::validate_license;
use crate::session_context::SessionContext;
use crate::audit::AuditEvent;
use crate::loa::LOA;

fn main() {
    let banner = r#"
███████╗██╗ ██████╗ ██╗██╗     
██╔════╝██║██╔════╝ ██║██║     
███████╗██║██║  ███╗██║██║     
╚════██║██║██║   ██║██║██║     
███████║██║╚██████╔╝██║███████╗
╚══════╝╚═╝ ╚═════╝ ╚═╝╚══════╝                          
Sigil Runtime
"#;

    println!("{}", banner);

    // Load config
    let config_result = load_config(std::env::var("MMF_CONFIG_PATH").ok().as_deref());

    let config_data = match config_result {
        Ok(cfg) => {
            println!("✅ Config loaded: {}", cfg.audit.context.as_deref().unwrap_or("unspecified"));
            cfg
        },
        Err(e) => {
            eprintln!("❌ Failed to load config: {}", e);
            exit(1);
        }
    };

    // Validate license
    let license_path = std::env::var("SIGIL_LICENSE_PATH").unwrap_or_else(|_| "sigil_license.toml".into());

    let license_result = validate_license(
        &license_path,
        &config_data.config.trust.allow_operator_canon_write.to_string(), // Placeholder
        &config_data.config.data_dir // Used as canonical fingerprint for now
    );

    let license = match license_result {
        Ok(validated) if validated.valid => {
            println!("✅ License validated: {}", validated.license.owner.name);
            Some(validated.license)
        },
        Ok(invalid) => {
            eprintln!("⚠️ License rejected: {}", invalid.message);
            None
        },
        Err(e) => {
            eprintln!("❌ Failed to parse license: {}", e);
            None
        }
    };

    // Construct runtime session
    let context = SessionContext::new(config_data.config.clone(), license);
    println!("🔐 Session Started: {}", context.summary_string());

    // Trust-level branch: Observer vs Operator vs Root
    match context.loa {
        LOA::Root => {
            println!("🚨 Elevated session running under LOA::Root");
            // TODO: Start Canon edit shell / runtime interface
        },
        LOA::Operator => {
            println!("🔧 Operator session active.");
            // TODO: Load tool modules, mutation disabled if required
        },
        LOA::Observer => {
            println!("👀 Observer mode: read-only diagnostics");
            // TODO: Allow introspection, audit replay, validator tools
        },
	LOA::Mentor => {
	    println!(".... Mentor session active.");
            // TODO: Limited mutation priv, audit-only mode?
	}
    }

    // Final audit (Codex Rule Zero: trust transparency)
    let audit = AuditEvent::new(
        &context.identity_hash(),
        "main_bootstrap",
        &context.session_id,
        "main.rs"
    )
    .with_severity(crate::audit::LogLevel::Info)
    .with_context(format!("Session bootstrap complete"));

    if let Err(e) = audit.write_to_log() {
        eprintln!("⚠️ Failed to write audit log: {}", e);
    }
}
