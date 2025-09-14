use crate::secure_file_ops::SecureFileOperations;
use clap::{Parser, Subcommand};
use std::sync::{Arc, RwLock};

/// Helper function to find a key file in secure locations
fn find_key_file(key_id: &str) -> Option<String> {
    crate::key_manager::find_key_file(key_id).map(|path| path.to_string_lossy().to_string())
}

/// Top-level CLI interface for Sigil
#[derive(Parser)]
#[command(
    name = "sigil",
    version = "0.1.0",
    author = "LOA::Root",
    about = "Sigil Modular AI Runtime CLI"
)]
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

    /// Register an extension module with the runtime
    RegisterExtension {
        #[arg(long)]
        name: String,
        #[arg(long)]
        loa: String,
    },

    /// Serve the HTTP API (trust routes, health, versioned endpoints)
    Serve {
        /// Host/IP to bind
        #[arg(long, default_value = "0.0.0.0")]
        host: String,
        /// Port to bind
        #[arg(long, default_value_t = 8080)]
        port: u16,
    },

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

    /// Generate a new license
    GenerateLicense {
        #[arg(long)]
        owner_name: String,
        #[arg(long)]
        owner_email: String,
        #[arg(long)]
        loa: String, // "Guest", "Observer", "Operator", "Mentor", "Root"
        #[arg(long)]
        expires_days: Option<u32>, // Days from now, default 90
        #[arg(long)]
        signing_key_id: String,
        #[arg(short, long)]
        output: String,
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
            // For backwards compatibility, support both file-based and CanonStore-based validation
            if file == "canon_store" || file == "store" {
                // Validate records from CanonStore
                use crate::canon_store::CanonStore;

                use crate::license_validator::load_current_loa;
                use std::sync::{Arc, Mutex};

                let loa = match load_current_loa() {
                    Ok(loa) => loa,
                    Err(e) => {
                        eprintln!("Failed to determine LOA: {e}");
                        return;
                    }
                };

                // Use encrypted Sled backend with proper key management
                let encryption_key = match crate::keys::KeyManager::get_encryption_key() {
                    Ok(key) => key,
                    Err(e) => {
                        eprintln!("Failed to get encryption key: {e}");
                        return;
                    }
                };
                let store = match crate::canon_store_sled_encrypted::CanonStoreSled::new(
                    "data/canon_store",
                    &encryption_key,
                ) {
                    Ok(s) => Arc::new(Mutex::new(s)),
                    Err(e) => {
                        eprintln!("Failed to open encrypted canon store: {e}");
                        return;
                    }
                };

                let records = {
                    let store_guard = store.lock().unwrap();
                    store_guard.list_records(None, &loa)
                };

                println!("Validating {} records from CanonStore:", records.len());
                for (i, record) in records.iter().enumerate() {
                    // Validate CanonicalRecord structure
                    let mut validation_errors = Vec::new();

                    // Check required fields
                    if record.id.is_empty() {
                        validation_errors.push("ID cannot be empty");
                    }
                    if record.kind.is_empty() {
                        validation_errors.push("Kind cannot be empty");
                    }
                    if record.tenant.is_empty() {
                        validation_errors.push("Tenant cannot be empty");
                    }
                    if record.space.is_empty() {
                        validation_errors.push("Space cannot be empty");
                    }
                    if record.hash.is_empty() {
                        validation_errors.push("Hash cannot be empty");
                    }

                    // Validate hash format (should be hex)
                    if !record.hash.chars().all(|c| c.is_ascii_hexdigit()) {
                        validation_errors.push("Hash must be valid hex");
                    }

                    // Validate signature and public key consistency
                    if record.sig.is_some() != record.pub_key.is_some() {
                        validation_errors
                            .push("Signature and public key must both be present or both be None");
                    }

                    if validation_errors.is_empty() {
                        println!("Record [{}] ({}) valid.", i, record.id);
                    } else {
                        eprintln!(
                            "Record [{}] ({}) failed: {}",
                            i,
                            record.id,
                            validation_errors.join(", ")
                        );
                    }
                }
            } else {
                eprintln!(
                    "File-based canon validation is deprecated. Use 'canon_store' or 'store' to validate records from the Canon store."
                );
                eprintln!(
                    "Legacy format validation has been retired in favor of CanonStore-based operations."
                );
            }
        }

        Commands::Diff { id } => {
            // Initialize encrypted canon store for diff operation
            use crate::canon_diff_chain::diff_by_id_with_store;
            use crate::license_validator::load_current_loa;
            use std::sync::{Arc, Mutex};

            let loa = match load_current_loa() {
                Ok(loa) => loa,
                Err(e) => {
                    eprintln!("Failed to determine LOA: {e}");
                    return;
                }
            };
            let store = {
                let encryption_key = match crate::keys::KeyManager::get_encryption_key() {
                    Ok(k) => k,
                    Err(e) => {
                        eprintln!("Failed to get encryption key: {e}");
                        return;
                    }
                };
                match crate::canon_store_sled_encrypted::CanonStoreSled::new(
                    "data/canon_store",
                    &encryption_key,
                ) {
                    Ok(s) => Arc::new(Mutex::new(s)),
                    Err(e) => {
                        eprintln!("Failed to open encrypted canon store: {e}");
                        return;
                    }
                }
            };

            match diff_by_id_with_store(store, &id, &loa) {
                Ok(diff) => {
                    if diff.is_empty() {
                        println!("No differences found for record '{}'", id);
                    } else {
                        println!("Differences for record '{}':", id);
                        for (key, value) in diff {
                            println!("  {}: {}", key, value);
                        }
                    }
                }
                Err(e) => eprintln!("Diff failed: {e}"),
            }
        }
        Commands::Revert { id, to_hash } => {
            // Initialize encrypted canon store for revert operation
            use crate::canon_store::revert_node_with_store;
            use crate::license_validator::load_current_loa;
            use std::sync::{Arc, Mutex};

            let loa = match load_current_loa() {
                Ok(loa) => loa,
                Err(e) => {
                    eprintln!("Failed to determine LOA: {e}");
                    return;
                }
            };
            let store = {
                let encryption_key = match crate::keys::KeyManager::get_encryption_key() {
                    Ok(k) => k,
                    Err(e) => {
                        eprintln!("Failed to get encryption key: {e}");
                        return;
                    }
                };
                match crate::canon_store_sled_encrypted::CanonStoreSled::new(
                    "data/canon_store",
                    &encryption_key,
                ) {
                    Ok(s) => Arc::new(Mutex::new(s)),
                    Err(e) => {
                        eprintln!("Failed to open encrypted canon store: {e}");
                        return;
                    }
                }
            };

            match revert_node_with_store(store, &id, &to_hash, &loa) {
                Ok(_) => println!(
                    "✅ Successfully reverted record '{}' to hash '{}'",
                    id, to_hash
                ),
                Err(e) => eprintln!("Revert failed: {e}"),
            }
        }
        Commands::Whoami => match crate::license_validator::load_current_loa() {
            Ok(loa) => println!("You are operating as {loa:?}"),
            Err(e) => eprintln!("LOA detection failed: {e}"),
        },
        Commands::RegisterExtension { name, loa } => {
            if let Err(e) = crate::extensions::register_extension(&name, &loa) {
                eprintln!("Failed to register extension: {e}");
            }
        }
        Commands::Serve { host, port } => {
            // Build a runtime core using env/TOML-backed config
            let addr = format!("{host}:{port}");

            let build_runtime =
                || -> Result<Arc<RwLock<crate::sigil_runtime_core::SigilRuntimeCore>>, String> {
                    use crate::config_loader::load_config;
                    use crate::loa::LOA;
                    use crate::runtime_config::{EnforcementMode, RuntimeConfig};
                    use crate::sigil_runtime_core::SigilRuntimeCore;
                    use std::sync::Mutex;

                    // Load app config (mmf.toml and MMF_* env)
                    let app_cfg =
                        load_config().map_err(|e| format!("Failed to load config: {e}"))?;

                    // Map config to runtime config
                    let enforcement_mode =
                        match app_cfg.irl.enforcement_mode.to_lowercase().as_str() {
                            "active" => EnforcementMode::Active,
                            "strict" => EnforcementMode::Strict,
                            _ => EnforcementMode::Active,
                        };

                    let runtime_cfg = RuntimeConfig {
                        active_model: None,
                        threshold: app_cfg.irl.threshold,
                        enforcement_mode,
                        telemetry_enabled: false,
                        explanation_enabled: false,
                        model_refresh_from_canon: app_cfg.irl.model_refresh_from_canon,
                    };

                    // Use encrypted Sled backend with proper key management
                    let encryption_key = crate::keys::KeyManager::get_encryption_key()
                        .map_err(|e| format!("Failed to get encryption key: {e}"))?;
                    let store = crate::canon_store_sled_encrypted::CanonStoreSled::new(
                        "data/canon_store",
                        &encryption_key,
                    )
                    .map_err(|e| format!("Failed to create encrypted canon store: {e}"))?;
                    let canon_store = Arc::new(Mutex::new(store));

                    let runtime = SigilRuntimeCore::new(LOA::Observer, canon_store, runtime_cfg)
                        .map_err(|e| format!("Failed to initialize runtime: {e}"))?;

                    // IRL telemetry/explainer removed
                    // Telemetry and explanation enabling is now handled by the runtime constructor.

                    Ok(Arc::new(RwLock::new(runtime)))
                };

            let runtime = match build_runtime() {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("Failed to initialize server runtime: {e}");
                    return;
                }
            };

            let app = crate::sigilweb::build_trust_router(runtime);

            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("Failed to build Tokio runtime: {e}");
                    return;
                }
            };

            rt.block_on(async move {
                let socket_addr: std::net::SocketAddr = match addr.parse() {
                    Ok(a) => a,
                    Err(e) => {
                        eprintln!("Invalid bind address {addr}: {e}");
                        return;
                    }
                };
                match tokio::net::TcpListener::bind(socket_addr).await {
                    Ok(listener) => {
                        println!("HTTP server listening on http://{addr}");
                        if let Err(e) = axum::serve(listener, app).await {
                            eprintln!("Server error: {e}");
                        }
                    }
                    Err(e) => eprintln!("Failed to bind {addr}: {e}"),
                }
            });
        }
        Commands::GenerateKey {
            key_id,
            key_type,
            output,
        } => {
            use crate::key_manager::{KeyManager, KeyType};

            let key_type_enum = match key_type.as_str() {
                "license" => KeyType::LicenseSigning,
                "canon" => KeyType::CanonSealing,
                "witness" => KeyType::WitnessSigning,
                _ => {
                    eprintln!(
                        "Invalid key type: {key_type}. Must be 'license', 'canon', or 'witness'",
                    );
                    return;
                }
            };

            let mut manager = KeyManager::new();
            match manager.generate_key(&key_id, key_type_enum) {
                Ok(key_pair) => {
                    println!("✅ Generated key pair: {key_id}");
                    println!("Public key: {}", key_pair.public_key);

                    if let Some(output_path) = output {
                        match key_pair.save_to_file(&output_path) {
                            Ok(_) => println!("💾 Key pair saved to: {output_path}"),
                            Err(e) => eprintln!("❌ Failed to save key pair: {e}"),
                        }
                    } else {
                        // Save to secure directory by default
                        match crate::key_manager::get_default_key_path(&key_id) {
                            Ok(default_path) => {
                                match key_pair.save_to_file(&default_path.to_string_lossy()) {
                                    Ok(_) => println!(
                                        "💾 Key pair saved to secure location: {}",
                                        default_path.display()
                                    ),
                                    Err(e) => {
                                        eprintln!("❌ Failed to save key pair: {e}");
                                        println!("🔑 Private key: {}", key_pair.private_key);
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("❌ Failed to create secure key directory: {e}");
                                println!("🔑 Private key: {}", key_pair.private_key);
                            }
                        }
                    }
                }
                Err(e) => eprintln!("❌ Failed to generate key pair: {e}"),
            }
        }
        Commands::Sign {
            key_id,
            data,
            output,
        } => {
            // Find the key file in secure locations
            let key_path = match find_key_file(&key_id) {
                Some(path) => path,
                None => {
                    eprintln!("❌ Key file not found: {key_id}.json");
                    eprintln!("   Searched in: current directory and secure key directory");
                    return;
                }
            };

            match crate::key_manager::SigilKeyPair::load_from_file(&key_path) {
                Ok(key_pair) => match key_pair.sign(data.as_bytes()) {
                    Ok(signature) => {
                        println!("✅ Data signed successfully");
                        println!("Signature: {signature}");

                        if let Some(output_path) = output {
                            // Use secure file operations
                            let secure_file_ops = SecureFileOperations::new(
                                vec![
                                    std::env::current_dir()
                                        .unwrap()
                                        .to_string_lossy()
                                        .to_string(),
                                ],
                                1024 * 1024, // 1MB max
                            );

                            match secure_file_ops {
                                Ok(ops) => {
                                    match ops.write_file_secure(
                                        std::path::Path::new(&output_path),
                                        signature.as_bytes(),
                                    ) {
                                        Ok(_) => println!(
                                            "💾 Signature saved securely to: {output_path}"
                                        ),
                                        Err(e) => {
                                            eprintln!("❌ Failed to save signature securely: {e}")
                                        }
                                    }
                                }
                                Err(e) => {
                                    eprintln!(
                                        "❌ Failed to initialize secure file operations: {e}"
                                    );
                                    // Fall back to regular file write
                                    match std::fs::write(&output_path, signature) {
                                        Ok(_) => println!("💾 Signature saved to: {output_path}"),
                                        Err(e) => eprintln!("❌ Failed to save signature: {e}"),
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => eprintln!("❌ Failed to sign data: {e}"),
                },
                Err(e) => eprintln!("❌ Failed to load key pair: {e}"),
            }
        }
        Commands::Verify {
            key_id,
            data,
            signature,
        } => {
            // Find the key file in secure locations
            let key_path = match find_key_file(&key_id) {
                Some(path) => path,
                None => {
                    eprintln!("❌ Key file not found: {key_id}.json");
                    eprintln!("   Searched in: current directory and secure key directory");
                    return;
                }
            };

            match crate::key_manager::SigilKeyPair::load_from_file(&key_path) {
                Ok(key_pair) => match key_pair.verify(data.as_bytes(), &signature) {
                    Ok(is_valid) => {
                        if is_valid {
                            println!("✅ Signature verified successfully!");
                        } else {
                            println!("❌ Signature verification failed!");
                        }
                    }
                    Err(e) => eprintln!("❌ Failed to verify signature: {e}"),
                },
                Err(e) => eprintln!("❌ Failed to load key pair: {e}"),
            }
        }
        Commands::GenerateLicense {
            owner_name,
            owner_email,
            loa,
            expires_days,
            signing_key_id,
            output,
        } => {
            generate_license_command(
                &owner_name,
                &owner_email,
                &loa,
                expires_days.unwrap_or(90),
                &signing_key_id,
                &output,
            );
        }
    }
}

/// Generate a signed license file
fn generate_license_command(
    owner_name: &str,
    owner_email: &str,
    loa_str: &str,
    expires_days: u32,
    signing_key_id: &str,
    output: &str,
) {
    use crate::loa::LOA;
    use chrono::{Duration, Utc};
    use sha2::{Digest, Sha256};
    use std::fs;
    use uuid::Uuid;

    // Parse LOA
    let loa = match loa_str.to_lowercase().as_str() {
        "guest" => LOA::Guest,
        "observer" => LOA::Observer,
        "operator" => LOA::Operator,
        "mentor" => LOA::Mentor,
        "root" => LOA::Root,
        _ => {
            eprintln!(
                "❌ Invalid LOA: {loa_str}. Must be Guest, Observer, Operator, Mentor, or Root"
            );
            return;
        }
    };

    // Load signing key from disk using platform-appropriate paths
    use crate::key_manager::SigilKeyPair;
    let home_dir = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".to_string());
    let key_path = format!("{}/.sigil/keys/{}.json", home_dir, signing_key_id);

    let signing_key = match SigilKeyPair::load_from_file(&key_path) {
        Ok(key) => key,
        Err(_) => {
            eprintln!(
                "❌ Signing key '{signing_key_id}' not found at: {}",
                key_path
            );
            eprintln!("Generate one first with:");
            eprintln!(
                "   cargo run --bin mmf_sigil generate-key --key-id {signing_key_id} --key-type license"
            );
            return;
        }
    };

    let now = Utc::now();
    let expires_at = now + Duration::days(expires_days as i64);
    let license_id = format!("sigil-license-{}", Uuid::new_v4().simple());

    // Generate owner hash_id from email (deterministic but privacy-preserving)
    let mut hasher = Sha256::new();
    hasher.update(owner_email.as_bytes());
    hasher.update(b"sigil-license-salt"); // Add salt to prevent rainbow tables
    let hash_id = format!("{:x}", hasher.finalize())[..16].to_string();

    // Create license structure matching sigil_license.toml format
    let license_toml = format!(
        r#"# Sigil Protocol License File
# Generated on {generated_at}
# Valid from {issued_at} until {expires_at}

[license]
id = "{license_id}"
issuedAt = "{issued_at}"
expiresAt = "{expires_at}"
loa = "{loa_name}"
scope = ["canon:system", "module:builtin", "runtime:sigil"]
issuer = "sigil_trust_v1"
version = "1.0"

[license.owner]
name = "{owner_name}"
mnemonic = "Generated-{short_id}"
email = "{owner_email}"
hashId = "{hash_id}"

[license.bindings]
canonFingerprint = "sha256:placeholder-will-be-computed-at-runtime"
runtimeId = "sigil-runtime-{runtime_id}"

[license.trust]
trustModel = "sigil_trust_v1"
signature = "ed25519:{signature_placeholder}"
sealed = true

[license.permissions]
canMutateCanon = {can_mutate_canon}
canOverrideAudit = {can_override_audit}
canRegisterModule = {can_register_module}
canElevateIdentity = {can_elevate_identity}

[license.audit]
lastVerified = "{issued_at}"
verifier = "sigil-license-generator"
canonicalized = true
"#,
        generated_at = now.format("%Y-%m-%d %H:%M:%S UTC"),
        license_id = license_id,
        issued_at = now.to_rfc3339(),
        expires_at = expires_at.to_rfc3339(),
        loa_name = format!("{:?}", loa),
        owner_name = owner_name,
        short_id = &hash_id[..8],
        owner_email = owner_email,
        hash_id = hash_id,
        runtime_id = Uuid::new_v4().simple(),
        signature_placeholder = "placeholder-will-be-computed",
        can_mutate_canon = matches!(loa, LOA::Root | LOA::Mentor),
        can_override_audit = matches!(loa, LOA::Root),
        can_register_module = matches!(loa, LOA::Root | LOA::Mentor | LOA::Operator),
        can_elevate_identity = matches!(loa, LOA::Root | LOA::Mentor),
    );

    // Note: License signature is placeholder. Manual signing required.
    // Implementation planned for future version with proper Ed25519 signing

    match fs::write(output, license_toml) {
        Ok(()) => {
            println!("✅ License generated: {output}");
            println!("📋 License Details:");
            println!("   Owner: {owner_name} <{owner_email}>");
            println!("   LOA: {:?}", loa);
            println!("   Valid until: {}", expires_at.format("%Y-%m-%d"));
            println!("   License ID: {license_id}");
            println!();
            println!("⚠️  Note: License signature is placeholder. Manual signing required.");
            println!("🔑 Public Key: {}", signing_key.public_key);
        }
        Err(e) => {
            eprintln!("❌ Failed to write license file: {e}");
        }
    }
}
