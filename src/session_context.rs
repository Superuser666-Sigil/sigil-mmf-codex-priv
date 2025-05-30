pub struct SessionContext {
    pub session_id: String,
}

pub fn detect_ephemeral_mode() -> bool {
    std::env::var("SIGIL_EPHEMERAL").unwrap_or_else(|_| "0".into()) == "1"
}
