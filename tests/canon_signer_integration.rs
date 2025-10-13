//! Integration tests for the canon_signer binary
//!
//! These tests verify the critical cryptographic operations of the Canon signing tool.

use std::fs;
use std::process::Command;
use tempfile::TempDir;

/// Test that the canon_signer binary can generate keys
#[test]
fn test_canon_signer_generate_key() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let key_path = temp_dir.path().join("test_key.json");

    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "canon_signer",
            "--",
            "generate-key",
            "--output",
            key_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute canon_signer");

    // Should succeed
    assert!(
        output.status.success(),
        "canon_signer generate-key failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Key file should exist
    assert!(key_path.exists(), "Key file was not created");

    // Key file should be valid JSON
    let key_content = fs::read_to_string(&key_path).expect("Failed to read key file");

    let _key_json: serde_json::Value =
        serde_json::from_str(&key_content).expect("Key file is not valid JSON");
}

/// Test that the canon_signer binary shows help
#[test]
fn test_canon_signer_help() {
    let output = Command::new("cargo")
        .args(["run", "--bin", "canon_signer", "--", "--help"])
        .output()
        .expect("Failed to execute canon_signer");

    // Should succeed
    assert!(output.status.success(), "canon_signer --help failed");

    // Should contain expected help text
    let help_text = String::from_utf8_lossy(&output.stdout);
    assert!(
        help_text.contains("Sign Canon records"),
        "Help text missing description"
    );
    assert!(
        help_text.contains("generate-key"),
        "Help text missing generate-key command"
    );
    assert!(
        help_text.contains("sign-file"),
        "Help text missing sign-file command"
    );
}

/// Test that canon_signer fails gracefully with invalid arguments
#[test]
fn test_canon_signer_invalid_args() {
    let output = Command::new("cargo")
        .args(["run", "--bin", "canon_signer", "--", "invalid-command"])
        .output()
        .expect("Failed to execute canon_signer");

    // Should fail
    assert!(
        !output.status.success(),
        "canon_signer should fail with invalid command"
    );

    // Should show error message
    let error_text = String::from_utf8_lossy(&output.stderr);
    assert!(!error_text.is_empty(), "Should have error output");
}
