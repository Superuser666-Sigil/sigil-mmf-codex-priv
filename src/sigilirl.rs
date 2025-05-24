// Canon-Compliant sigilirl.rs
// Purpose: CLI tool for MMF+Sigil trust model training, listing, and enforcement via IRL

use clap::{App, Arg, SubCommand};
use crate::irl_train_tool::train_model;
use crate::irl_runtime::TrustGuard;
use crate::canon_store_sled::CanonStoreSled;
use crate::config_loader::load_config;
use crate::license_validator::validate_license;
use crate::session_context::SessionContext;
use crate::audit::{AuditEvent, LogLevel};

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = App::new("sigilirl")
        .version("1.0")
        .author("MMF + Sigil Runtime Team")
        .about("Manage trust models in the Sigil Protocol runtime")
        .subcommand(SubCommand::with_name("train")
            .about("Train a new IRL trust model from audit logs")
            .arg(Arg::with_name("audit-log").required(true))
            .arg(Arg::with_name("name").required(true))
            .arg(Arg::with_name("category").default_value("default")))
        .subcommand(SubCommand::with_name("list")
            .about("List known trust evaluations"))
        .subcommand(SubCommand::with_name("enforce")
            .about("Run IRL enforcement against a given input")
            .arg(Arg::with_name("input").required(true)))
        .get_matches();

    let config = load_config().map_err(|e| format!("Config load failed: {}", e))?;
    validate_license(&config)?;

    let store_path = config.get("store_path").ok_or("Missing 'store_path'")?;
    let operator_write = config.get("operator_write")
        .map(|v| v == "true")
        .unwrap_or(false);

    let key_b64 = config.get("encryption_key_b64").map(|s| s.as_str());

    let store = CanonStoreSled::new(store_path, operator_write, key_b64);
    let ctx = SessionContext::bootstrap()?;

    if let Some(train_matches) = matches.subcommand_matches("train") {
        let audit_log = train_matches.value_of("audit-log")
            .ok_or("Missing audit-log")?;
        let name = train_matches.value_of("name")
            .ok_or("Missing model name")?;
        let category = train_matches.value_of("category").unwrap_or("default");

        train_model(audit_log, name, category, &store, &ctx)?;
        AuditEvent::log_simple("irl_model_train", LogLevel::Info);
    } else if matches.subcommand_matches("list").is_some() {
        TrustGuard::list_all(&store)?;
        AuditEvent::log_simple("irl_model_list", LogLevel::Info);
    } else if let Some(enforce_matches) = matches.subcommand_matches("enforce") {
        let input = enforce_matches.value_of("input")
            .ok_or("Missing input")?;
        TrustGuard::enforce(input, &store, &ctx)?;
        AuditEvent::log_simple("irl_model_enforce", LogLevel::Info);
    } else {
        println!("No subcommand provided. Use --help.");
    }

    Ok(())
}