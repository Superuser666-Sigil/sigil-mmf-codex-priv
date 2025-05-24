use clap::{Parser, Subcommand};
use chrono::Utc;

/// Top-level CLI interface for Sigil
#[derive(Parser)]
#[command(name = "sigil", version = "0.1.0", author = "LOA::Root", about = "Sigil Modular AI Runtime CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run the Sigil Canon session (load + validate + score + audit)
    Run,

    /// Seal a single Canon entry
    Seal {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        output: String,
    },

    /// Validate Canon entries (structural only)
    Validate {
        #[arg(short, long)]
        file: String,
    },

    /// Train IRL models
    IrlTrain {
        #[arg(short, long)]
        audit_log: Option<String>,
    },

    /// Diff a Canon node by ID
    Diff {
        #[arg(short, long)]
        id: String,
    },

    /// Revert a Canon node by ID to a previous hash
    Revert {
        #[arg(short, long)]
        id: String,
        #[arg(short, long)]
        to_hash: String,
    },

    /// Display current LOA identity
    Whoami,
}

pub fn dispatch(cli: Cli) {
    match cli.command {
        Commands::Run => {
            crate::sigil_session::start_sigil_session();
        }
        Commands::Seal { input, output } => {
            match crate::sealtool::seal_canon_entry(&input, &output) {
                Ok(_) => println!("Entry sealed and saved to {}", output),
                Err(e) => eprintln!("Seal failed: {}", e),
            }
        }
        Commands::Validate { file } => {
            match crate::canon_loader::load_canon_entries(&file) {
                Ok(entries) => {
                    for (i, entry) in entries.iter().enumerate() {
                        match crate::canon_validator::validate_entry(entry) {
                            Ok(_) => println!("Entry [{}] valid.", i),
                            Err(e) => eprintln!("Entry [{}] failed: {}", i, e),
                        }
                    }
                }
                Err(e) => eprintln!("Failed to load file: {}", e),
            }
        }
        Commands::IrlTrain { audit_log } => {
            crate::sigilirl::run_training_cli(audit_log);
        }
        Commands::Diff { id } => {
            match crate::canon_diff_chain::diff_by_id(&id) {
                Ok(diff) => println!("{}", diff),
                Err(e) => eprintln!("Diff failed: {}", e),
            }
        }
        Commands::Revert { id, to_hash } => {
            match crate::canon_store::revert_node(&id, &to_hash) {
                Ok(_) => println!("Reverted {} to {}", id, to_hash),
                Err(e) => eprintln!("Revert failed: {}", e),
            }
        }
        Commands::Whoami => {
            match crate::license_validator::load_current_loa() {
                Ok(loa) => println!("You are operating as {:?}", loa),
                Err(e) => eprintln!("LOA detection failed: {}", e),
            }
        }
    }
}
