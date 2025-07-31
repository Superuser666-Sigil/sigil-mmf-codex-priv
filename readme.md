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
- Python 3.8+ (for legacy ONNX trainer comparison)

### Building
```bash
cargo build --release
```

### Basic Usage
```bash
# Check system status
cargo run --bin mmf_sigil -- whoami

# Train a trust model with ONNX export
cargo run --bin trainer -- --csv data.csv --mode trust --output model.onnx --save-to-canon

# Initialize Canon storage
cargo run --bin mmf_sigil -- canon-init --backend sled
```

## Current Implementation Status

### ✅ **Fully Implemented**
- **Access Control**: Complete LOA system with role-based permissions
- **Audit System**: Two-phase reasoning chains with cryptographic verification
- **Canon Storage**: Multi-backend persistence with validation
- **License Framework**: Cryptographic license validation and enforcement
- **CLI Interface**: Comprehensive command-line tools
- **ONNX Training**: Rust-native model training with export capabilities

### 🚧 **In Development**
- **IRL Training Pipeline**: Gradient computation currently disabled, loss calculation functional
- **Model Loading**: ONNX model import and inference integration
- **Web Interface**: REST API and dashboard (scaffold implemented)

### 📋 **Planned**
- **Semantic Validation**: Natural language coherence checking for Canon mutations
- **Ethics Enforcement**: Runtime ethical constraint validation
- **Distributed Canon**: Multi-node canonical storage with consensus

## Key Features

### Trust-First Architecture
- Every output includes provenance and reasoning traces
- Cryptographic audit trails prevent tampering
- Access controls enforce principle of least privilege

### Model Training & Export
```bash
# Train relational architecture for trust scoring
cargo run --bin trainer -- \
  --csv trust_data.csv \
  --mode trust \
  --relational \
  --output trust_model.onnx \
  --save-to-canon
```

### Canon Management
```bash
# Add validated knowledge to Canon
cargo run --bin mmf_sigil -- canon-add --file knowledge.jsonl

# Query Canon with audit trail
cargo run --bin mmf_sigil -- canon-query --pattern "user_behavior"
```

## License & Governance

Sigil operates under the **MMF Codex License** framework, which requires:
- Valid cryptographic licenses for runtime operation
- Compliance with canonical knowledge constraints
- Audit trail maintenance for all system modifications

See `MMF-CL_v1.1.md` for complete license terms.

## Technical Documentation

- **Architecture**: See `codex_manifest_rule_zero.md` for philosophical foundations
- **API Reference**: Generated docs via `cargo doc --open`
- **Examples**: Reference implementations in `examples/` directory

## Contributing

Sigil is designed for mission-critical applications requiring verifiable trustworthiness. Contributions must maintain the framework's core principles:

1. **Transparency**: All behavior must be explainable and auditable
2. **Access Control**: Changes must respect LOA hierarchy
3. **Immutability**: Audit trails and frozen reasoning chains cannot be modified

## Contact

For technical questions or collaboration opportunities regarding the Sigil framework, please review the documentation and implementation before reaching out.

**Keywords**: trustworthy AI, runtime verification, access control, audit trails, Rust, ONNX, IRL, transparency