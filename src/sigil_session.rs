use crate::config_loader::load_config;

pub fn start_sigil_session() {
    let config = load_config();
    if let Err(e) = crate::sigil_runtime_core::run_sigil_session(&config) {
        eprintln!("Failed to start sigil session: {e}");
    }
}
