// module_loader.rs - Integrates canon validation during module load

use std::fs;
use std::path::Path;
use crate::canon_validator::validate_canon_file;

pub fn load_module(manifest_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let raw = fs::read_to_string(manifest_path)?;
    let module: toml::de::Value = toml::de::from_str(&raw)?;

    // Extract module info
    let module_id = module["module"]["id"].as_str().unwrap_or("Unknown");
    println!("Loading module: {}", module_id);

    // Perform Canon Validation (Checks for schema compliance)
    let canon_path = Path::new("modules/mmf-shadowrun-core/canon/sr6e.json");
    match validate_canon_file(&canon_path) {
        Ok(_) => println!("Canon file validated successfully."),
        Err(e) => {
            println!("ERROR: Canon validation failed: {}", e);
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, e)));
        }
    }

    // Proceed to load the rest of the module or abort if validation fails
    println!("Module loaded successfully: {}", module_id);

    Ok(())
}
