// Sigil Runtime - main.rs
// Bootstrap runner compliant with Codex Rule Zero, Canon LOA policies, and IRL trace audit

use clap::Parser;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
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
    // Initialize structured logging (JSON) with env-configurable level
    // Falls back to sensible defaults without panicking if initialization fails
    if !tracing::dispatcher::has_been_set() {
        let default_filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info,mmf_sigil=info".to_string());
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new(default_filter))
            .json()
            .with_current_span(true)
            .with_target(true)
            .with_timer(tracing_subscriber::fmt::time::UtcTime::rfc_3339())
            .flatten_event(true)
            .finish();
        if let Err(e) = tracing::dispatcher::set_global_default(subscriber.into()) {
            eprintln!("Failed to initialize tracing subscriber: {e}");
        }
    }
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

    info!(message = "Sigil Runtime starting", banner = %banner);

    // Load config
    let config_data = match load_config() {
        Ok(cfg) => cfg,
        Err(e) => {
            error!(message = "Failed to load config", error = %e);
            return;
        }
    };

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
            info!(
                message = "License validated",
                owner = %validated.license.owner.name
            );
            validated.license.loa
        }
        Ok(invalid) => {
            warn!(message = "License rejected", reason = %invalid.message);
            LOA::Guest
        }
        Err(e) => {
            error!(message = "Failed to parse license", error = %e);
            LOA::Guest
        }
    };

    // Construct runtime session
    let context = SessionContext::new("main_session", loa);
    info!(
        message = "Session started",
        session_id = %context.session_id,
        loa = ?context.loa
    );

    // Trust-level branch: Observer vs Operator vs Root
    match context.loa {
        LOA::Root => {
            warn!(message = "Elevated session running under LOA::Root");
            sigilctl::run_root_shell(&context);
        }
        LOA::Operator => {
            info!(message = "Operator session active");
            if let Err(e) = module_loader::load_and_run_modules(&context) {
                warn!(message = "Module loading failed", error = %e);
            }
        }
        LOA::Observer => {
            info!(message = "Observer mode: read-only diagnostics");
            audit_verifier::run_observer_tools(&context);
        }
        _ => {
            info!(message = "Guest or Mentor session active");
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
        warn!(message = "Failed to write audit log", error = %e);
    }
}
