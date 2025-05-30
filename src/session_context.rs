pub struct SessionContext {
    pub session_id: String,
}

pub fn detect_ephemeral_mode() -> bool {
    std::env::var("SIGIL_EPHEMERAL").unwrap_or_else(|_| "0".into()) == "1"
}

impl SessionContext {
    pub fn new(session_id: &str, loa: crate::loa::LOA) -> Self {
        SessionContext {
            session_id: session_id.to_string(),
            loa,
            ..Default::default()
        }
    }
}
