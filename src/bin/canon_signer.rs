//! Canon Record Signer
//! 
//! This tool signs Canon records with persistent Ed25519 keys.
//! It reads CanonicalRecord JSON files, recomputes their canonical JSON,
//! updates the hash, and signs them with a persistent key.

use mmf_sigil::canonical_record::CanonicalRecord;
use mmf_sigil::keys::{CanonSigningKey, KeyManager};
use sha2::{Sha256, Digest};
use std::fs;
use std::path::PathBuf;
use clap::{Parser, Subcommand};
use base64::Engine;

#[derive(Parser)]
#[command(name = "canon_signer")]
#[command(about = "Sign Canon records with persistent Ed25519 keys")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new signing key
    GenerateKey {
        /// Output path for the key file
        #[arg(short, long, default_value = "keys/canon_signing_key.json")]
        output: PathBuf,
    },
    /// Sign a single Canon record file
    SignFile {
        /// Input JSONL file with Canon records
        #[arg(short, long)]
        input: PathBuf,
        /// Output JSONL file for signed records
        #[arg(short, long)]
        output: PathBuf,
        /// Key file to use for signing
        #[arg(short, long)]
        key: Option<PathBuf>,
    },
    /// Sign multiple Canon record files
    SignBatch {
        /// Directory containing JSONL files
        #[arg(short, long)]
        input_dir: PathBuf,
        /// Output directory for signed files
        #[arg(short, long)]
        output_dir: PathBuf,
        /// Key file to use for signing
        #[arg(short, long)]
        key: Option<PathBuf>,
    },
    /// Verify signatures in Canon record files
    Verify {
        /// File to verify
        #[arg(short, long)]
        file: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    let cli = Cli::parse();
    
    match cli.command {
        Commands::GenerateKey { output } => {
            generate_key(output)?;
        }
        Commands::SignFile { input, output, key } => {
            sign_file(input, output, key)?;
        }
        Commands::SignBatch { input_dir, output_dir, key } => {
            sign_batch(input_dir, output_dir, key)?;
        }
        Commands::Verify { file } => {
            verify_file(file)?;
        }
    }
    
    Ok(())
}

fn generate_key(output: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    println!("Generating new Canon signing key...");
    
    let key = CanonSigningKey::generate();
    
    // Ensure output directory exists
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    
    key.save_to_file(&output, "Canon record signing")?;
    
    println!("✅ Key generated and saved to: {}", output.display());
    println!("🔑 Public key: {}", key.public_key_b64());
    
    Ok(())
}

fn load_signing_key(key_path: Option<PathBuf>) -> Result<CanonSigningKey, Box<dyn std::error::Error>> {
    match key_path {
        Some(path) => {
            println!("Loading signing key from: {}", path.display());
            Ok(CanonSigningKey::load_from_file(path)?)
        }
        None => {
            println!("Using default Canon signing key...");
            Ok(KeyManager::get_or_create_canon_key()?)
        }
    }
}

fn sign_file(input: PathBuf, output: PathBuf, key_path: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = load_signing_key(key_path)?;
    
    println!("🔍 Reading Canon records from: {}", input.display());
    let content = fs::read_to_string(&input)?;
    
    let mut signed_records = Vec::new();
    let mut records_processed = 0;
    
    for (line_num, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        
        let mut record: CanonicalRecord = serde_json::from_str(line)
            .map_err(|e| format!("Error parsing line {}: {}", line_num + 1, e))?;
        
        // Re-canonicalize and sign the record
        sign_record(&mut record, &signing_key)?;
        signed_records.push(serde_json::to_string(&record)?);
        records_processed += 1;
    }
    
    // Ensure output directory exists
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    
    // Write signed records
    fs::write(&output, signed_records.join("\n"))?;
    
    println!("✅ Signed {} records and saved to: {}", records_processed, output.display());
    println!("🔑 Signed with public key: {}", signing_key.public_key_b64());
    
    Ok(())
}

fn sign_batch(input_dir: PathBuf, output_dir: PathBuf, key_path: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = load_signing_key(key_path)?;
    
    println!("🔍 Processing JSONL files in: {}", input_dir.display());
    
    // Ensure output directory exists
    fs::create_dir_all(&output_dir)?;
    
    let mut total_processed = 0;
    
    for entry in fs::read_dir(&input_dir)? {
        let entry = entry?;
        let path = entry.path();
        
        if path.extension().and_then(|s| s.to_str()) == Some("jsonl") {
            let output_file = output_dir.join(path.file_name().unwrap());
            println!("📝 Processing: {} -> {}", path.display(), output_file.display());
            
            let content = fs::read_to_string(&path)?;
            let mut signed_records = Vec::new();
            let mut file_records_processed = 0;
            
            for (line_num, line) in content.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                
                let mut record: CanonicalRecord = serde_json::from_str(line)
                    .map_err(|e| format!("Error parsing {}:{}: {}", path.display(), line_num + 1, e))?;
                
                sign_record(&mut record, &signing_key)?;
                signed_records.push(serde_json::to_string(&record)?);
                file_records_processed += 1;
            }
            
            fs::write(&output_file, signed_records.join("\n"))?;
            println!("  ✅ Signed {} records", file_records_processed);
            total_processed += file_records_processed;
        }
    }
    
    println!("🎉 Batch complete! Signed {} total records", total_processed);
    println!("🔑 Signed with public key: {}", signing_key.public_key_b64());
    
    Ok(())
}

fn sign_record(record: &mut CanonicalRecord, signing_key: &CanonSigningKey) -> Result<(), Box<dyn std::error::Error>> {
    // The records are already canonicalized with computed hashes.
    // We should not re-canonicalize them as that would change the hash.
    // Instead, we'll use the existing canonical representation to sign.
    
    // For now, let's create a copy without sig fields for canonical representation
    let mut canonical_record = record.clone();
    canonical_record.sig = None;
    canonical_record.pub_key = None;
    canonical_record.witnesses = vec![];
    
    // Generate canonical JSON from the unsigned version
    let canonical_json = canonical_record.to_canonical_json()
        .map_err(|e| format!("Failed to canonicalize record {}: {}", record.id, e))?;
    
    let canonical_bytes = canonical_json.as_bytes();
    
    // Recompute hash using our JCS canonicalization (RFC 8785)
    let computed_hash = hex::encode(Sha256::digest(canonical_bytes));
    if computed_hash != record.hash {
        println!("🔄 Updating hash for record {} to JCS-canonical hash", record.id);
        println!("   Old: {}", record.hash);
        println!("   New: {}", computed_hash);
        record.hash = computed_hash;
    }
    
    // Sign the canonical bytes and get (sig_b64, pub_key_b64)
    let (sig_b64, pub_key_b64) = signing_key.sign_record(canonical_bytes);
    record.sig = Some(sig_b64);
    record.pub_key = Some(pub_key_b64);
    
    Ok(())
}

fn verify_file(file: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Verifying signatures in: {}", file.display());
    
    let content = fs::read_to_string(&file)?;
    let mut records_verified = 0;
    let mut records_failed = 0;
    
    for (line_num, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        
        let record: CanonicalRecord = serde_json::from_str(line)
            .map_err(|e| format!("Error parsing line {}: {}", line_num + 1, e))?;
        
        match verify_record(&record) {
            Ok(()) => {
                records_verified += 1;
                println!("  ✅ {} - signature valid", record.id);
            }
            Err(e) => {
                records_failed += 1;
                println!("  ❌ {} - {}", record.id, e);
            }
        }
    }
    
    println!("📊 Verification complete:");
    println!("  ✅ Valid: {}", records_verified);
    println!("  ❌ Failed: {}", records_failed);
    
    if records_failed > 0 {
        std::process::exit(1);
    }
    
    Ok(())
}

fn verify_record(record: &CanonicalRecord) -> Result<(), Box<dyn std::error::Error>> {
    // Check if record is signed
    let sig_b64 = record.sig.as_ref()
        .ok_or("Record is not signed (sig is null)")?;
    let pub_key_b64 = record.pub_key.as_ref()
        .ok_or("Record has no public key (pub_key is null)")?;
    
    // Use the canonicalize_record function directly to ensure consistency with signing
    let canonical_json = mmf_sigil::canonicalize::canonicalize_record(record)
        .map_err(|e| format!("Failed to canonicalize: {}", e))?;
    let canonical_bytes = canonical_json.as_bytes();
    
    // Verify the hash
    let computed_hash = hex::encode(Sha256::digest(canonical_bytes));
    if computed_hash != record.hash {
        // Debug output for the first few characters to see the difference
        let canonical_preview = if canonical_json.len() > 100 { 
            &canonical_json[..100] 
        } else { 
            &canonical_json 
        };
        eprintln!("DEBUG - Record {}", record.id);
        eprintln!("DEBUG - Canonical preview: {}", canonical_preview);
        eprintln!("DEBUG - Canonical length: {}", canonical_json.len());
        return Err(format!("Hash mismatch: expected {}, got {}", record.hash, computed_hash).into());
    }
    
    // Load the public key and verify signature
    let pub_key_bytes = base64::engine::general_purpose::STANDARD.decode(pub_key_b64)?;
    if pub_key_bytes.len() != 32 {
        return Err(format!("Invalid public key length: {}", pub_key_bytes.len()).into());
    }
    
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
        &pub_key_bytes.try_into().unwrap()
    )?;
    
    let sig_bytes = base64::engine::general_purpose::STANDARD.decode(sig_b64)?;
    if sig_bytes.len() != 64 {
        return Err(format!("Invalid signature length: {}", sig_bytes.len()).into());
    }
    
    let signature = ed25519_dalek::Signature::from_bytes(
        &sig_bytes.try_into().unwrap()
    );
    
    use ed25519_dalek::Verifier;
    verifying_key.verify(canonical_bytes, &signature)?;
    
    Ok(())
}
