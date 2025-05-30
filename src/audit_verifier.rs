
use sha2::{Sha256, Digest};
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
        let hash_hex = format!("{:x}", hash);

        println!("Line {} hash: {}", line_number + 1, hash_hex);
        previous_hash = Some(hash_hex);
    }

    Ok(())
}
