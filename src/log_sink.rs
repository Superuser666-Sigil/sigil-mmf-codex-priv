use chrono::{DateTime, Utc};
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;

#[derive(Debug, Clone)]
pub struct LogEvent {
    pub timestamp: DateTime<Utc>,
    pub level: String,
    pub message: String,
}

impl LogEvent {
    pub fn new(level: &str, message: &str) -> Self {
        LogEvent {
            timestamp: Utc::now(),
            level: level.to_string(),
            message: message.to_string(),
        }
    }

    pub fn new_with_context(
        level: &str,
        message: &str,
        context: Option<&str>,
        category: Option<&str>,
    ) -> Self {
        let mut full_message = message.to_string();

        if let Some(ctx) = context {
            full_message.push_str(&format!(" [Context: {ctx}]"));
        }

        if let Some(cat) = category {
            full_message.push_str(&format!(" [Category: {cat}]"));
        }

        LogEvent {
            timestamp: Utc::now(),
            level: level.to_string(),
            message: full_message,
        }
    }

    pub fn write_to(&self, path: &str) -> std::io::Result<()> {
        // Ensure directory exists
        if let Some(parent) = std::path::Path::new(path).parent() {
            create_dir_all(parent)?;
        }

        let file = OpenOptions::new().create(true).append(true).open(path)?;

        let mut writer = std::io::BufWriter::new(file);
        let log_line = format!(
            "[{}] {}: {}\n",
            self.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            self.level.to_uppercase(),
            self.message
        );

        write!(writer, "{log_line}")?;
        writer.flush()?;

        Ok(())
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "timestamp": self.timestamp.to_rfc3339(),
            "level": self.level,
            "message": self.message
        })
    }
}
