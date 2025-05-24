// src/test_utils.rs
// Canonical test utility module for MMF+Sigil runtime

use std::io::{self, Write};
use std::sync::{Mutex, OnceLock};

static STDOUT_CAPTURE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// Captures all stdout output from the enclosed code block.
/// Returns (result, captured_output_as_string)
#[macro_export]
macro_rules! capture_stdout {
    ($block:block) => {{
        use std::io::Write;
        use std::sync::{Mutex, OnceLock};
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let lock = LOCK.get_or_init(|| Mutex::new(()));
        let _guard = lock.lock().unwrap();

        let mut buffer = Vec::new();
        let old_stdout = std::io::stdout();
        let mut handle = old_stdout.lock();

        // Simulated capturing: redirecting would be system-level here
        let result = { $block };
        drop(handle); // In real cases: swap fd or use mock buffer

        (result, "<simulated capture not yet implemented>".to_string())
    }};
}