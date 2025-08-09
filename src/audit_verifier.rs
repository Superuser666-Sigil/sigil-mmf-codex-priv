use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufRead, BufReader};

pub fn verify_audit_log(path: &str) -> Result<(), String> {
    let file = File::open(path).map_err(|_| "Cannot open audit log")?;
    let reader = BufReader::new(file);

    let mut previous_hash = None;

    for (line_number, line) in reader.lines().enumerate() {
        let line = line.map_err(|_| "Line read error")?;
        let mut hasher = Sha256::new();

        if let Some(prev) = &previous_hash {
            hasher.update(prev);
        }
        hasher.update(&line);
        let hash = hasher.finalize();
        let hash_hex = format!("{hash:x}");

        println!("Line {} hash: {}", line_number + 1, hash_hex);
        previous_hash = Some(hash_hex);
    }

    Ok(())
}

pub fn run_observer_tools(ctx: &crate::session_context::SessionContext) {
    println!(
        "[ObserverTools] Audit and verification tools active for session {}",
        ctx.session_id
    );

    let log_path = "logs/audit_access_log.jsonl";
    println!("[ObserverTools] Displaying audit log: {log_path}");

    let file = match File::open(log_path) {
        Ok(file) => file,
        Err(e) => {
            println!("[ObserverTools] Could not open audit log: {e}");
            return;
        }
    };

    let reader = BufReader::new(file);
    for (index, line) in reader.lines().enumerate() {
        match line {
            Ok(line_content) => {
                println!("[Line {}] {}", index + 1, line_content);
            }
            Err(e) => {
                println!("[ObserverTools] Error reading line {}: {}", index + 1, e);
            }
        }
    }
}
