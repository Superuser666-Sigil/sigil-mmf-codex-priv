
use std::io::{self, Write};

pub fn display_status(ctx: &crate::session_context::SessionContext) {
    println!("[status] session active: {}", ctx.session_id);
}

// Missing functions that are referenced in other modules
pub fn warn_user(_message: &str) {
    println!("[WARNING] {_message}");
}

pub fn notify_success(_message: &str) {
    println!("[SUCCESS] {_message}");
}

pub fn log_loa_violation(_user_loa: &crate::loa::LOA, _required_loa: &crate::loa::LOA) {
    println!("[LOA VIOLATION] User has {_user_loa:?}, required {_required_loa:?}");
}

pub fn run_root_shell(ctx: &crate::session_context::SessionContext) {
    println!("SIGIL ROOT SHELL [session: {}]", ctx.session_id);
    println!("Type 'help' for a list of commands.");

    loop {
        print!("~> ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            warn_user("Failed to read command");
            continue;
        }

        let parts: Vec<&str> = input.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let command = parts[0];
        let _args = &parts[1..];

        match command {
            "help" => {
                println!("Available commands:");
                println!("  help          - Show this help message");
                println!("  status        - Display the current session status");
                println!("  exit          - Exit the shell");
            }
            "status" => {
                display_status(ctx);
            }
            "exit" => {
                notify_success("Exiting root shell.");
                break;
            }
            _ => {
                warn_user(&format!("Unknown command: {command}"));
            }
        }
    }
}