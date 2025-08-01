use clap::{Parser, Subcommand};

/// Helper function to find a key file in secure locations
fn find_key_file(key_id: &str) -> Option<String> {
    match crate::key_manager::find_key_file(key_id) {
        Some(path) => Some(path.to_string_lossy().to_string()),
        None => None,
    }
}

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

    /// Generate a new cryptographic key pair
    GenerateKey {
        #[arg(short, long)]
        key_id: String,
        #[arg(long, default_value = "license")]
        key_type: String,
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Sign data with a key
    Sign {
        #[arg(short, long)]
        key_id: String,
        #[arg(long)]
        data: String,
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Verify a signature
    Verify {
        #[arg(short, long)]
        key_id: String,
        #[arg(long)]
        data: String,
        #[arg(long)]
        signature: String,
    },
}

pub fn dispatch(cli: Cli) {
    match cli.command {
        Commands::Run => {
            crate::sigil_session::start_sigil_session();
        }
        Commands::Seal { input, output } => {
            // For now, just print the input and output paths
            println!("Sealing entry from {input} to {output}");
            println!("Seal functionality not yet implemented");
        }
        Commands::Validate { file } => {
            match crate::canon_loader::load_canon_entries(&file) {
                Ok(entries) => {
                    for (i, entry) in entries.iter().enumerate() {
                        // Convert CanonNode to serde_json::Value for validation
                        let entry_json = serde_json::to_value(entry)
                            .unwrap_or_else(|_| serde_json::json!({}));
                        match crate::canon_validator::validate_entry(&entry_json) {
                            Ok(_) => println!("Entry [{i}] valid."),
                            Err(e) => eprintln!("Entry [{i}] failed: {e}"),
                        }
                    }
                }
                Err(e) => eprintln!("Failed to load file: {e}"),
            }
        }
        Commands::IrlTrain { audit_log } => {
            crate::sigilirl::run_training_cli(audit_log);
        }
        Commands::Diff { id } => {
            match crate::canon_diff_chain::diff_by_id(&id) {
                Ok(diff) => println!("{diff:?}"),
                Err(e) => eprintln!("Diff failed: {e}"),
            }
        }
        Commands::Revert { id, to_hash } => {
            match crate::canon_store::revert_node(&id, &to_hash) {
                Ok(_) => println!("Reverted {id} to {to_hash}"),
                Err(e) => eprintln!("Revert failed: {e}"),
            }
        }
        Commands::Whoami => {
            match crate::license_validator::load_current_loa() {
                Ok(loa) => println!("You are operating as {loa:?}"),
                Err(e) => eprintln!("LOA detection failed: {e}"),
            }
        }
        Commands::GenerateKey { key_id, key_type, output } => {
            use crate::key_manager::{KeyManager, KeyType};
            
            let key_type_enum = match key_type.as_str() {
                "license" => KeyType::LicenseSigning,
                "canon" => KeyType::CanonSealing,
                "witness" => KeyType::WitnessSigning,
                _ => {
                    eprintln!("Invalid key type: {}. Must be 'license', 'canon', or 'witness'", key_type);
                    return;
                }
            };
            
            let mut manager = KeyManager::new();
            match manager.generate_key(&key_id, key_type_enum) {
                Ok(key_pair) => {
                    println!("✅ Generated key pair: {}", key_id);
                    println!("Public key: {}", key_pair.public_key);
                    
                    if let Some(output_path) = output {
                        match key_pair.save_to_file(&output_path) {
                            Ok(_) => println!("💾 Key pair saved to: {}", output_path),
                            Err(e) => eprintln!("❌ Failed to save key pair: {}", e),
                        }
                    } else {
                        // Save to secure directory by default
                        match crate::key_manager::get_default_key_path(&key_id) {
                            Ok(default_path) => {
                                match key_pair.save_to_file(&default_path.to_string_lossy()) {
                                    Ok(_) => println!("💾 Key pair saved to secure location: {}", default_path.display()),
                                    Err(e) => {
                                        eprintln!("❌ Failed to save key pair: {}", e);
                                        println!("🔑 Private key: {}", key_pair.private_key);
                                    }
                                }
                            },
                            Err(e) => {
                                eprintln!("❌ Failed to create secure key directory: {}", e);
                                println!("🔑 Private key: {}", key_pair.private_key);
                            }
                        }
                    }
                },
                Err(e) => eprintln!("❌ Failed to generate key pair: {}", e),
            }
        }
        Commands::Sign { key_id, data, output } => {
            
            // Find the key file in secure locations
            let key_path = match find_key_file(&key_id) {
                Some(path) => path,
                None => {
                    eprintln!("❌ Key file not found: {}.json", key_id);
                    eprintln!("   Searched in: current directory and secure key directory");
                    return;
                }
            };
            
            match crate::key_manager::SigilKeyPair::load_from_file(&key_path) {
                Ok(key_pair) => {
                    match key_pair.sign(data.as_bytes()) {
                        Ok(signature) => {
                            println!("✅ Data signed successfully");
                            println!("Signature: {}", signature);
                            
                            if let Some(output_path) = output {
                                match std::fs::write(&output_path, signature) {
                                    Ok(_) => println!("💾 Signature saved to: {}", output_path),
                                    Err(e) => eprintln!("❌ Failed to save signature: {}", e),
                                }
                            }
                        },
                        Err(e) => eprintln!("❌ Failed to sign data: {}", e),
                    }
                },
                Err(e) => eprintln!("❌ Failed to load key pair: {}", e),
            }
        }
        Commands::Verify { key_id, data, signature } => {
            // Find the key file in secure locations
            let key_path = match find_key_file(&key_id) {
                Some(path) => path,
                None => {
                    eprintln!("❌ Key file not found: {}.json", key_id);
                    eprintln!("   Searched in: current directory and secure key directory");
                    return;
                }
            };
            
            match crate::key_manager::SigilKeyPair::load_from_file(&key_path) {
                Ok(key_pair) => {
                    match key_pair.verify(data.as_bytes(), &signature) {
                        Ok(is_valid) => {
                            if is_valid {
                                println!("✅ Signature verified successfully!");
                            } else {
                                println!("❌ Signature verification failed!");
                            }
                        },
                        Err(e) => eprintln!("❌ Failed to verify signature: {}", e),
                    }
                },
                Err(e) => eprintln!("❌ Failed to load key pair: {}", e),
            }
        }
    }
}
