# TODO Implementation Roadmap

This document catalogs all TODO items found in the codebase and provides implementation guidance based on authoritative Rust best practices.

## License Signing Implementation

**Location**: `src/cli.rs:651`
**Current State**: Placeholder comment for license signing functionality
**Priority**: HIGH (security-critical)

### Requirements Analysis
Based on [The Rust Book §9 (Error Handling)](https://doc.rust-lang.org/book/ch09-00-error-handling.html) and [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/):

1. **Cryptographic Signing**: Implement proper Ed25519 signature generation using `ed25519-dalek`
2. **Error Handling**: Use `thiserror` for typed errors, avoid panics in public APIs
3. **Input Validation**: Validate all license parameters before signing
4. **Audit Trail**: Log all signing operations for compliance

### Implementation Plan
```rust
// Replace TODO with proper implementation
pub fn sign_license_content(
    content: &str,
    signing_key: &SigilKeyPair,
) -> Result<String, LicenseSigningError> {
    // Validate content
    if content.is_empty() {
        return Err(LicenseSigningError::EmptyContent);
    }
    
    // Generate signature
    let signature = signing_key.sign(content.as_bytes())?;
    
    // Return base64-encoded signature
    Ok(base64::encode(signature.to_bytes()))
}
```

### Error Types
```rust
#[derive(Error, Debug)]
pub enum LicenseSigningError {
    #[error("Empty license content")]
    EmptyContent,
    #[error("Signing failed: {source}")]
    SigningFailed {
        #[from]
        source: ed25519_dalek::Error,
    },
}
```

## Model Refresh Configuration Flag

**Location**: `src/sigil_runtime_core.rs:245`
**Current State**: Placeholder for config-based model refresh control
**Priority**: MEDIUM (feature enhancement)

### Requirements Analysis
Based on [The Rust Book §6 (Enums and Pattern Matching)](https://doc.rust-lang.org/book/ch06-00-enums.html) and [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/):

1. **Configuration Integration**: Add flag to existing config structure
2. **Runtime Control**: Allow dynamic enabling/disabling of model refresh
3. **Backward Compatibility**: Maintain existing behavior when flag is not set
4. **Validation**: Ensure flag values are within acceptable ranges

### Implementation Plan
```rust
// Add to config structure
#[derive(Debug, Clone, Deserialize)]
pub struct RuntimeConfig {
    // ... existing fields ...
    pub model_refresh_from_canon: bool,
}

// Update runtime logic
if config.model_refresh_from_canon {
    runtime.refresh_models_from_canon()?;
} else {
    tracing::info!("Model refresh from canon disabled via config");
}
```

### Configuration Schema
```toml
[runtime]
model_refresh_from_canon = true  # Enable automatic model refresh
```

## Additional TODO Items Found

### Console Output Migration
**Priority**: MEDIUM (code quality)
**Files Affected**: Multiple source files
**Action**: Replace all `println!`/`eprintln!` with structured logging using `tracing`

### Error Handling Standardization
**Priority**: HIGH (reliability)
**Files Affected**: Test files, some source files
**Action**: Replace `unwrap()`/`expect()` with proper error handling using `?` operator

### Documentation Completion
**Priority**: MEDIUM (maintainability)
**Files Affected**: All public modules
**Action**: Add comprehensive doc comments for all public APIs

## Implementation Guidelines

### 1. Follow Rust Book Patterns
- **Error Handling**: Use `Result<T, E>` and `?` operator per [Book §9](https://doc.rust-lang.org/book/ch09-02-recoverable-errors-with-result.html)
- **Ownership**: Follow borrowing rules per [Book §4](https://doc.rust-lang.org/book/ch04-00-understanding-ownership.html)
- **Testing**: Implement comprehensive tests per [Book §11](https://doc.rust-lang.org/book/ch11-00-testing.html)

### 2. Adhere to API Guidelines
- **Naming**: Use consistent naming conventions
- **Documentation**: Include examples in doc comments
- **Error Types**: Use `thiserror` for library errors

### 3. Security Considerations
- **Input Validation**: Validate all external inputs
- **Cryptographic Operations**: Use established crates (ed25519-dalek, sha2)
- **Audit Logging**: Log all security-critical operations

### 4. Performance Guidelines
- **Minimal Allocations**: Use references and borrowing where possible
- **Async Operations**: Use Tokio runtime consistently
- **Resource Management**: Implement proper cleanup and resource limits

## Timeline and Dependencies

1. **Week 1**: Implement license signing functionality
2. **Week 2**: Add configuration flag for model refresh
3. **Week 3**: Migrate console output to structured logging
4. **Week 4**: Standardize error handling across codebase
5. **Week 5**: Complete documentation and final testing

## References

- [The Rust Book](https://doc.rust-lang.org/book/)
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- [Rustonomicon](https://doc.rust-lang.org/nomicon/)
- [Cargo Book](https://doc.rust-lang.org/cargo/)
- [ed25519-dalek Documentation](https://docs.rs/ed25519-dalek/)
- [tracing Documentation](https://docs.rs/tracing/)

