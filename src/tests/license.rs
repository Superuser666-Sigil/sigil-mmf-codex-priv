#[cfg(test)]
mod tests {
    use super::*;
    use crate::license_validator::validate_license;
    
    #[test]
    #[test]
    fn test_valid_license_should_pass() {
        let result = validate_license("tests/assets/sigil_license_valid.toml", "test-runtime", "test-fp");
        assert!(result.is_ok());
        let license = result.unwrap();
        assert!(license.valid);
        assert_eq!(license.license.owner.name, "Dave");
    }
    
    #[test]
    #[test]
    fn test_expired_license_should_fail() {
        let result = validate_license("tests/assets/sigil_license_expired.toml", "test-runtime", "test-fp").unwrap();
        assert!(!result.valid);
        assert_eq!(result.irl_score, 0.0);
    }
    
    #[test]
    #[test]
    fn test_mismatched_runtime_should_score_0_2() {
        let result = validate_license("tests/assets/sigil_license_bad_runtime.toml", "test-runtime", "test-fp").unwrap();
        assert!(!result.valid);
        assert_eq!(result.irl_score, 0.2);
    }
    
    #[test]
    #[test]
    fn test_mismatched_fingerprint_should_score_0_4() {
        let result = validate_license("tests/assets/sigil_license_bad_fp.toml", "test-runtime", "test-fp").unwrap();
        assert!(!result.valid);
        assert_eq!(result.irl_score, 0.4);
    }
    
    #[test]
    #[test]
    fn test_unsealed_license_should_score_0_5() {
        let result = validate_license("tests/assets/sigil_license_unsealed.toml", "test-runtime", "test-fp").unwrap();
        assert!(!result.valid);
        assert_eq!(result.irl_score, 0.5);
    }
    
    #[test]
    #[test]
    fn test_missing_license_block_should_error() {
        let result = validate_license("tests/assets/sigil_license_missing_header.toml", "test-runtime", "test-fp");
        assert!(result.is_err());
    }
    
    #[test]
    #[test]
    fn test_invalid_syntax_should_error() {
        let result = validate_license("tests/assets/sigil_license_invalid_syntax.toml", "test-runtime", "test-fp");
        assert!(result.is_err());
    }
}