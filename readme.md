# Sigil: Trustworthy AI Runtime Framework

Sigil is a Rust-based framework for building trustworthy AI systems through runtime enforcement of transparency, access control, and audit trails. Built on the principle that **"a piece of output that cannot explain itself has no trust"** (Rule Zero), Sigil provides cryptographic guarantees around AI behavior and decision-making.

## Architecture Overview

Sigil implements a comprehensive trust infrastructure through several key components:

### Core Systems
- **LOA (Level of Access)**: Hierarchical access control with cryptographic attestation (`Guest → Observer → Operator → Mentor → Root`)
- **Two-Phase Reasoning**: Mutable reasoning chains that freeze into immutable audit records
- **Canon Storage**: Versioned, validated truth storage with multiple backends (Sled, encrypted Sled, Codex Nexus)
- **IRL Trust Scoring**: Inverse Reinforcement Learning for behavioral trust evaluation

### Security & Compliance
- **License Validation**: Cryptographic license enforcement with expiration and scope controls
- **Audit Chain**: Immutable audit trails with cryptographic integrity verification
- **Session Management**: Secure context tracking and permission enforcement

## Getting Started

### Prerequisites
- Rust 1.70+ (stable-x86_64-pc-windows-msvc recommended for Windows)
- Cargo (latest stable)

### Building
```bash
# Clean build
cargo clean
cargo build --release

# Development build
cargo build
```

### Basic Usage
```bash
# Check system status
cargo run --bin mmf_sigil -- whoami

# Train a neural network model
cargo run --bin trainer -- --model-type unified --mode trust

# Train relational architecture
cargo run --bin trainer -- --model-type relational --mode trust

# Initialize Canon storage
cargo run --bin mmf_sigil -- canon-init --backend sled
```

## Current Implementation Status

### ✅ **Fully Implemented & Working**
- **Access Control**: Complete LOA system with role-based permissions
- **Audit System**: Two-phase reasoning chains with cryptographic verification
- **Canon Storage**: Multi-backend persistence with validation
- **License Framework**: Cryptographic license validation and enforcement
- **CLI Interface**: Comprehensive command-line tools
- **Neural Network Training**: Working training pipeline using Candle framework
- **Cross-Platform Key Management**: OS-agnostic secure key storage
- **Model Export**: Basic model saving functionality

### 🚧 **Partially Implemented**
- **IRL Training Pipeline**: Framework exists but needs real data integration
- **Model Loading**: ONNX model import and inference integration
- **Web Interface**: REST API and dashboard (scaffold implemented)
- **Teacher Model Integration**: Knowledge distillation framework ready

### 📋 **Planned**
- **Real Data Integration**: Replace synthetic data with actual SigilDERG data
- **Semantic Validation**: Natural language coherence checking for Canon mutations
- **Ethics Enforcement**: Runtime ethical constraint validation
- **Distributed Canon**: Multi-node canonical storage with consensus

## Key Features

### Trust-First Architecture
- Every output includes provenance and reasoning traces
- Cryptographic audit trails prevent tampering
- Access controls enforce principle of least privilege

### Neural Network Training
```bash
# Train unified architecture
cargo run --bin trainer -- --model-type unified --mode trust

# Train relational architecture  
cargo run --bin trainer -- --model-type relational --mode trust

# Specify output path
cargo run --bin trainer -- --model-type unified --output-path ./models/my_model.safetensors
```

**Current Training Features:**
- ✅ **Candle Framework**: Stable ML framework (replaced problematic Burn)
- ✅ **AdamW Optimizer**: Working gradient descent with proper parameter updates
- ✅ **MSE Loss**: Mean squared error loss calculation
- ✅ **Model Saving**: Models saved to `./models/` directory
- ✅ **CLI Interface**: Full command-line argument parsing

**Training Data:**
- Currently using synthetic random data for testing
- Ready for integration with real SigilDERG data
- Supports both unified and relational architectures

### Canon Management
```bash
# Add validated knowledge to Canon
cargo run --bin mmf_sigil -- canon-add --file knowledge.jsonl

# Query Canon with audit trail
cargo run --bin mmf_sigil -- canon-query --pattern "user_behavior"
```

## Technical Stack

### Core Framework
- **Language**: Rust 2021 edition
- **ML Framework**: Candle (Hugging Face) - stable, production-ready
- **ONNX Support**: Tract-ONNX for model import/export
- **Storage**: Sled for embedded databases
- **Cryptography**: ed25519-dalek, AES-GCM, SHA2

### Dependencies
- **Web Framework**: Axum for REST APIs
- **CLI**: Clap for command-line interface
- **Serialization**: Serde for JSON/TOML handling
- **Async Runtime**: Tokio for async operations
- **Logging**: Tracing for structured logging

## Recent Major Changes

### Migration from Burn to Candle
- **Problem**: Burn 0.18.0 had persistent optimizer and trait bound issues
- **Solution**: Migrated to Candle 0.9.1 (Hugging Face framework)
- **Benefits**: 
  - ✅ Stable, production-ready ML framework
  - ✅ Working optimizers and gradient descent
  - ✅ Better documentation and community support
  - ✅ Cross-platform compatibility

### Cross-Platform Improvements
- **Key Management**: OS-agnostic secure directory handling
- **File Paths**: Platform-independent path resolution
- **Error Messages**: Cross-platform error reporting

## License & Governance

Sigil operates under the **MMF Codex License** framework, which requires:
- Valid cryptographic licenses for runtime operation
- Compliance with canonical knowledge constraints
- Audit trail maintenance for all system modifications

See `MMF-CL_v1.1.md` for complete license terms.

## Development

### Project Structure
```
src/
├── bin/
│   └── trainer.rs          # Neural network training binary
├── main.rs                 # Main CLI application
├── lib.rs                  # Core library
├── cli.rs                  # Command-line interface
├── key_manager.rs          # Cross-platform key management
├── canon_store.rs          # Canon storage backends
├── audit_chain.rs          # Audit trail system
├── loa.rs                  # Level of Access control
├── license_validator.rs    # License validation
└── ...                     # Additional modules
```

### Testing
```bash
# Run all tests
cargo test

# Run specific test module
cargo test --test license

# Check compilation
cargo check --bin trainer
cargo check --bin mmf_sigil
```

### Documentation
```bash
# Generate and open documentation
cargo doc --open

# Generate documentation for specific crate
cargo doc --package candle-nn --open
```

## Contributing

Sigil is designed for mission-critical applications requiring verifiable trustworthiness. Contributions must maintain the framework's core principles:

1. **Transparency**: All behavior must be explainable and auditable
2. **Access Control**: Changes must respect LOA hierarchy
3. **Immutability**: Audit trails and frozen reasoning chains cannot be modified
4. **Cross-Platform**: Code must work on Windows, Linux, and macOS

## Contact

For technical questions or collaboration opportunities regarding the Sigil framework, please review the documentation and implementation before reaching out.

**Keywords**: trustworthy AI, runtime verification, access control, audit trails, Rust, Candle, IRL, transparency, neural networks, machine learning