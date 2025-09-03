use crate::canon_loader::CanonNode;
use std::fs::{File, create_dir_all};
use std::io::Write;
use std::path::Path;

pub fn store_node_nexus(node: &CanonNode) -> std::io::Result<()> {
    let parts: Vec<&str> = node.id.split("::").collect();
    let dir = Path::new("canon_nexus")
        .join(parts.get(1).unwrap_or(&"unknown"))
        .join(parts.get(2).unwrap_or(&"unsorted"));

    create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", node.id.replace("::", "_")));

    let mut file = File::create(path)?;
    let serialized = serde_json::to_string_pretty(node).unwrap();
    file.write_all(serialized.as_bytes())?;
    Ok(())
}
