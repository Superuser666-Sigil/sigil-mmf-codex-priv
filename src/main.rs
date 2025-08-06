// Sigil Runtime - main.rs
// Bootstrap runner compliant with Codex Rule Zero, Canon LOA policies, and IRL trace audit

use clap::Parser;
use mmf_sigil::{
    audit::{AuditEvent, LogLevel},
    audit_verifier,
    cli::{dispatch, Cli},
    config_loader::load_config,
    license_validator::validate_license,
    loa::LOA,
    module_loader,
    session_context::SessionContext,
    sigilctl,
};

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

    // Check if CLI arguments are provided
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        // Use CLI mode
        let cli = Cli::parse();
        dispatch(cli);
        return;
    }

    println!("{banner}");

    // Load config
    let config_data = load_config();

    // Validate license
    let license_path =
        std::env::var("SIGIL_LICENSE_PATH").unwrap_or_else(|_| "sigil_license.toml".into());

    let license_result = validate_license(
        &license_path,
        &config_data.trust.allow_operator_canon_write.to_string(), // Placeholder
        "data_dir_placeholder", // Used as canonical fingerprint for now
    );

    let loa = match license_result {
        Ok(validated) if validated.valid => {
            println!("✅ License validated: {}", validated.license.owner.name);
            validated.license.loa
        }
        Ok(invalid) => {
            eprintln!("⚠️ License rejected: {}", invalid.message);
            LOA::Guest
        }
        Err(e) => {
            eprintln!("❌ Failed to parse license: {e}");
            LOA::Guest
        }
    };

    // Construct runtime session
    let context = SessionContext::new("main_session", loa);
    println!(
        "🔐 Session Started: {} (LOA: {:?})",
        context.session_id, context.loa
    );

    // Trust-level branch: Observer vs Operator vs Root
    match context.loa {
        LOA::Root => {
            println!("🚨 Elevated session running under LOA::Root");
            sigilctl::run_root_shell(&context);
        }
        LOA::Operator => {
            println!("🔧 Operator session active.");
            module_loader::load_and_run_modules(&context);
        }
        LOA::Observer => {
            println!("👀 Observer mode: read-only diagnostics");
            audit_verifier::run_observer_tools(&context);
        }
        _ => {
            println!("👤 Guest or Mentor session active.");
        }
    }

    // Final audit (Codex Rule Zero: trust transparency)
    let audit = AuditEvent::new(
        "main",
        "main_bootstrap",
        Some(&context.session_id),
        "main.rs",
        &context.loa,
    )
    .with_severity(LogLevel::Info)
    .with_context("Session bootstrap complete");

    if let Err(e) = audit.write_to_log() {
        eprintln!("⚠️ Failed to write audit log: {e}");
    }
}
