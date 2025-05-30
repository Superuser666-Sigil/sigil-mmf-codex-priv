
// Auto-generated CLI tool for Sigil IRL management

use clap::{App, Arg, SubCommand};
use mmf_sigil::irl_train_tool::train_model;
use mmf_sigil::irl_runtime::TrustGuard;
use mmf_sigil::canon_store_sled::CanonStoreSled;
use mmf_sigil::loa::LOA;
use mmf_sigil::config_loader::load_config;
use mmf_sigil::license_validator::validate_license;
use mmf_sigil::session_context::SessionContext;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = App::new("SigilIRL")
        .version("1.0")
        .author("Your Name")
        .about("Inverse Reinforcement Learning tools for Sigil Trust System")
        .subcommand(
            SubCommand::with_name("train")
                .about("Train a new IRL model from audit logs")
                .arg(Arg::with_name("audit-log")
                    .required(true)
                    .help("Path to audit log file"))
                .arg(Arg::with_name("name")
                    .required(true)
                    .help("Name for the new model"))
                .arg(Arg::with_name("category")
                    .default_value("trust_model")
                    .help("Category for the new model"))
                .arg(Arg::with_name("license")
                    .required(true)
                    .help("License token"))
        )
        .subcommand(
            SubCommand::with_name("list")
                .about("List available IRL models")
                .arg(Arg::with_name("license")
                    .required(true)
                    .help("License token"))
        )
        .subcommand(
            SubCommand::with_name("activate")
                .about("Activate a model for trust enforcement")
                .arg(Arg::with_name("model-id")
                    .required(true)
                    .help("ID of the model to activate"))
                .arg(Arg::with_name("threshold")
                    .default_value("0.0")
                    .help("Decision threshold"))
                .arg(Arg::with_name("license")
                    .required(true)
                    .help("License token"))
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("train") {
        let audit_log = matches.value_of("audit-log").unwrap();
        let name = matches.value_of("name").unwrap();
        let category = matches.value_of("category").unwrap();
        let license = matches.value_of("license").unwrap();
        
        match train_model(audit_log, name, category, license) {
            Ok(model_id) => println!("Model trained successfully. ID: {}", model_id),
            Err(e) => println!("Training failed: {}", e),
        }
    } else if let Some(matches) = matches.subcommand_matches("list") {
        let license = matches.value_of("license").unwrap();
        list_models(license)?;
    } else if let Some(matches) = matches.subcommand_matches("activate") {
        let model_id = matches.value_of("model-id").unwrap();
        let threshold: f64 = matches.value_of("threshold").unwrap().parse()?;
        let license = matches.value_of("license").unwrap();
        
        activate_model(model_id, threshold, license)?;
    } else {
        println!("No command specified. Use --help for usage information.");
    }
    
    Ok(())
}

fn list_models(license_token: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config();
    let license = validate_license(license_token, &config)?;
    let loa = license.loa.unwrap_or(LOA::Guest);

    if loa < LOA::Trusted {
        return Err("LOA::Trusted or higher required to list models".into());
    }

    let store = CanonStoreSled::new("data/canon", config.trust.allow_operator_canon_write);
    let entries = store.list_entries(Some("irl_reward"), &loa);

    if entries.is_empty() {
        println!("No IRL models found.");
        return Ok(());
    }

    println!("Found {} IRL models:", entries.len());
    for entry in entries {
        if let Ok(model) = serde_json::from_str::<mmf_sigil::irl_reward::RewardModel>(&entry.content) {
            println!("ID: {}", model.id);
            println!("  Name: {}", model.name);
            println!("  Category: {}", model.category);
            println!("  Confidence: {:.2}", model.confidence);
            println!("  Created: {}", model.timestamp);
            println!("  Source trajectories: {}", model.source_trajectories.len());
            println!();
        }
    }

    Ok(())
}

fn activate_model(model_id: &str, threshold: f64, license_token: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config();
    let license = validate_license(license_token, &config)?;
    let loa = license.loa.unwrap_or(LOA::Guest);

    if loa < LOA::Trusted {
        return Err("LOA::Trusted or higher required to activate models".into());
    }

    let store = CanonStoreSled::new("data/canon", config.trust.allow_operator_canon_write);
    let mut trust_guard = mmf_sigil::irl_runtime::TrustGuard::new(false);
    trust_guard.initialize(&store, &loa)?;
    trust_guard.set_active_model(model_id, threshold)?;

    let active_model = serde_json::json!({
        "model_id": model_id,
        "threshold": threshold,
        "activated_by": license.subject_id,
        "activated_at": chrono::Utc::now().to_rfc3339()
    });

    std::fs::write(
        "data/active_irl_model.json",
        serde_json::to_string_pretty(&active_model)?,
    )?;

    println!("Model {} activated with threshold {:.4}", model_id, threshold);
    println!("This model will be used for trust enforcement on startup.");

    Ok(())
}
