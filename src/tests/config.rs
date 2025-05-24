// tests/config.rs
use mmf_sigil::config::MMFConfig;
use std::env;

#[test]
pub fn valid_env_config_loads_successfully() {
    env::set_var("MMF_DATA_DIR", "/tmp/canon_data");
    env::set_var("MMF_AUDIT_LOG", "/tmp/audit.log");
    env::set_var("SIGIL_AES_KEY", "base64mocked==");
    env::set_var("MMF_TRUST_OP_WRITE", "true");

    let config = MMFConfig::from_env();
    assert!(config.is_ok());

    let cfg = config.unwrap();
    assert_eq!(cfg.data_dir, "/tmp/canon_data");
    assert_eq!(cfg.audit_log_path, "/tmp/audit.log");
    assert_eq!(cfg.encryption_key_b64.as_deref(), Some("base64mocked=="));
    assert!(cfg.trust.allow_operator_canon_write);
}

#[test]
pub fn missing_data_dir_fails_fast() {
    env::remove_var("MMF_DATA_DIR");
    env::set_var("MMF_AUDIT_LOG", "/tmp/audit.log");

    let result = MMFConfig::from_env();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("MMF_DATA_DIR"));
}

#[test]
pub fn missing_audit_log_fails_fast() {
    env::set_var("MMF_DATA_DIR", "/tmp/valid");
    env::remove_var("MMF_AUDIT_LOG");

    let result = MMFConfig::from_env();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("MMF_AUDIT_LOG"));
}

#[test]
pub fn empty_data_dir_fails() {
    env::set_var("MMF_DATA_DIR", "");
    env::set_var("MMF_AUDIT_LOG", "/some/path");

    let result = MMFConfig::from_env();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("cannot be empty"));
}

#[test]
pub fn operator_write_defaults_to_true() {
    env::set_var("MMF_DATA_DIR", "/any");
    env::set_var("MMF_AUDIT_LOG", "/any");
    env::remove_var("MMF_TRUST_OP_WRITE");

    let config = MMFConfig::from_env().unwrap();
    assert!(config.trust.allow_operator_canon_write);
}

#[test]
pub fn operator_write_false_input_disables_permission() {
    env::set_var("MMF_DATA_DIR", "/any");
    env::set_var("MMF_AUDIT_LOG", "/any");
    env::set_var("MMF_TRUST_OP_WRITE", "false");

    let config = MMFConfig::from_env().unwrap();
    assert!(!config.trust.allow_operator_canon_write);
}