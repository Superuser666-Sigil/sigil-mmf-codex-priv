use mmf_sigil::audit::{AuditEvent, LogLevel};
use mmf_sigil::loa::LOA;
use chrono::Utc;

#[test]
pub fn audit_event_structures_correctly() {
    let event = AuditEvent {
        timestamp: Utc::now(),
        action: "test_action".into(),
        id: "unit_subject".into(),
        loa: LOA::Root,
        level: LogLevel::Info,
    };

    assert_eq!(event.action, "test_action");
    assert_eq!(event.id, "unit_subject");
    assert_eq!(format!("{}", event.level), "INFO");
}

#[test]
pub fn audit_event_emits_to_writer_correctly() {
    let mut buffer = Vec::new();
    let event = AuditEvent {
        timestamp: Utc::now(),
        action: "emit_test".into(),
        id: "test_id".into(),
        loa: LOA::Root,
        level: LogLevel::Debug,
    };

    event.emit_to(&mut buffer).expect("emit_to failed");
    let output = String::from_utf8(buffer).expect("Invalid UTF-8");

    assert!(output.contains("emit_test"));
    assert!(output.contains("test_id"));
    assert!(output.contains("ROOT"));
}