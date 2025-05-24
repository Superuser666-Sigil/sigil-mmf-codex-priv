use crate::sigil_runtime_core::run_sigil_session;

/// Starts a Sigil inference or audit session
pub fn start_sigil_session() {
    let canon_path = "nomicon_canon_nodes.jsonl";  // Default Canon input path
    println!("Starting Sigil session using Canon at: {}", canon_path);
    run_sigil_session(canon_path);
}
