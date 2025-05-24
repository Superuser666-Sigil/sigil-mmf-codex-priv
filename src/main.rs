// Sigil Runtime - main.rs
// Bootstrap runner compliant with Codex Rule Zero, Canon LOA policies, and IRL trace audit

mod cli;
mod config;
mod config_loader;
mod license_validator;
mod session_context;
mod audit;
mod loa;
mod sigil_session;
mod sealtool;
mod canon_loader;
mod canon_validator;
mod sigilirl;
mod canon_diff_chain;
mod canon_store;

use clap::Parser;
use crate::cli::{Cli, Commands};
use std::process::exit;
use crate::config_loader::load_config;
use crate::license_validator::validate_license;
use crate::session_context::SessionContext;
use crate::audit::AuditEvent;
use crate::loa::LOA;

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Run => {
            println!("🚀 Running Sigil Canon session...");
            run_main_session();
        },
        Commands::Seal { input, output } => {
            println!("🔐 Sealing Canon entry from {} → {}", input, output);
            match crate::sealtool::seal_canon_entry(input, output) {
                Ok(msg) => println!("✅ {}", msg),
                Err(e) => eprintln!("❌ {}", e),
            }
        },
        Commands::Validate { file } => {
            println!("📄 Validating file: {}", file);
            match crate::canon_loader::load_canon_entries(file) {
                Ok(entries) => {
                    for entry in entries {
                        match crate::canon_validator::validate_entry(&entry) {
                            Ok(_) => println!("✅ Valid: {}", entry.id),
                            Err(e) => eprintln!("❌ Invalid: {}", e),
                        }
                    }
                },
                Err(e) => eprintln!("❌ Failed to load: {}", e),
            }
        },
        Commands::IrlTrain { audit_log } => {
            println!("🧠 Training IRL models...");
            crate::sigilirl::run_training_cli(audit_log);
        },
        Commands::Diff { id } => {
            println!("🧬 Diffing Canon node ID: {}", id);
            match crate::canon_diff_chain::diff_by_id(id) {
                Ok(result) => println!("{}", result),
                Err(e) => eprintln!("❌ {}", e),
            }
        },
        Commands::Revert { id, to_hash } => {
            println!("🔁 Reverting Canon node {} to {}", id, to_hash);
            match crate::canon_store::revert_node(id, to_hash) {
                Ok(_) => println!("✅ Node reverted."),
                Err(e) => eprintln!("❌ {}", e),
            }
        },
        Commands::Whoami => {
            println!("👤 Current LOA: {:?}", crate::license_validator::load_current_loa());
        }
    }
}

fn run_main_session() {
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

    let license_path = std::env::var("SIGIL_LICENSE_PATH").unwrap_or_else(|_| "sigil_license.toml".into());

    let license_result = validate_license(
        &license_path,
        &config_data.config.trust.allow_operator_canon_write.to_string(),
        &config_data.config.data_dir
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

    let context = SessionContext::new(config_data.config.clone(), license);
    println!("🔐 Session Started: {}", context.summary_string());

    match context.loa {
        LOA::Root => println!("🚨 Elevated session running under LOA::Root"),
        LOA::Operator => println!("🔧 Operator session active."),
        LOA::Observer => println!("👀 Observer mode: read-only diagnostics"),
        LOA::Mentor => println!("🧭 Mentor session active."),
    }

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