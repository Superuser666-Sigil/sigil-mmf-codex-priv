
use chrono::Utc;
use std::fs::{OpenOptions};
use std::io::Write;
use std::path::Path;

#[derive(Debug)]
pub struct LogEvent {
    pub module: String,
    pub message: String,
    pub session_id: Option<String>,
    pub tag: Option<String>,
}

impl LogEvent {
    pub fn new(module: &str, message: &str, session_id: Option<&str>, tag: Option<&str>) -> Self {
        LogEvent {
            module: module.into(),
            message: message.into(),
            session_id: session_id.map(|s| s.into()),
            tag: tag.map(|t| t.into()),
        }
    }

    pub fn write_to(&self, path: &str) -> Result<(), &'static str> {
        let log_path = Path::new(path);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .map_err(|_| "Failed to open log sink")?;

        let time = Utc::now().to_rfc3339();
        let formatted = format!(
            "[{}] [{}] [{}] {} {}",
            time,
            self.module,
            self.tag.clone().unwrap_or_else(|| "-".into()),
            self.session_id.clone().unwrap_or_else(|| "-".into()),
            self.message
        );

        writeln!(file, "{}", formatted).map_err(|_| "Failed to write log event")
    }
}
