# Sigil Key Management System

## Overview

The Sigil key management system provides secure, encrypted storage and rotation of Ed25519 signing keys used for Canon record integrity. All private keys are encrypted at rest using AES-256-GCM.

## Environment Configuration

### Required Environment Variables

#### `CANON_ENCRYPTION_KEY`
- **Purpose**: Base64-encoded 32-byte AES-256 encryption key for private key storage
- **Format**: Base64 string (44 characters)
- **Example**: `dGhpcyBpcyBhIDMyIGJ5dGUga2V5IGZvciBBRVMtMjU2LUdDTQo=`
- **Security**: **CRITICAL** - Store securely, rotate regularly
- **Default**: Uses development-only key (NOT secure for production)

### Optional Environment Variables

#### `CANON_KEY_DIR`
- **Purpose**: Directory for encrypted key storage
- **Default**: `keys/encrypted`
- **Example**: `/secure/path/to/keys`

#### `CANON_LEGACY_KEY_PATH`
- **Purpose**: Path to legacy unencrypted key (for migration)
- **Default**: `keys/canon_signing_key.json`
- **Example**: `/legacy/path/canon_signing_key.json`

## Key Lifecycle

### 1. Initial Setup

```bash
# Generate a secure encryption key
export CANON_ENCRYPTION_KEY=$(openssl rand -base64 32)

# Set secure key directory
export CANON_KEY_DIR="/secure/keys"

# Initialize key store (creates first signing key)
cargo run --bin sigil
```

### 2. Key Rotation

Keys should be rotated regularly for security. The system maintains all historical keys for signature verification.

```rust
use mmf_sigil::keys::KeyManager;

// Rotate to a new signing key
let mut store = KeyManager::get_or_create_key_store()?;
let new_key_index = KeyManager::rotate_keys(&mut store)?;
println!("Rotated to key index: {}", new_key_index);
```

### 3. Historical Verification

The system can verify signatures from any historical key:

```rust
// Load key store
let store = KeyManager::get_or_create_key_store()?;

// Verify signature with specific key version
let historical_key = store.get_key(key_index)?;
historical_key.verify_signature(canonical_bytes, signature_b64)?;
```

## Storage Format

### Encrypted Key File Structure

```json
{
  "version": 1,
  "encrypted_private_key_b64": "base64-encoded-encrypted-private-key",
  "public_key_b64": "base64-encoded-public-key",
  "nonce_b64": "base64-encoded-aes-gcm-nonce",
  "created_at": "2024-01-01T00:00:00Z",
  "key_index": 1,
  "purpose": "Canon record signing"
}
```

### Directory Structure

```
keys/encrypted/
├── canon_key_0001.json  # Historical key
├── canon_key_0002.json  # Historical key  
└── canon_key_0003.json  # Current key
```

## Security Considerations

### Encryption
- **Algorithm**: AES-256-GCM with 96-bit nonces
- **Key Derivation**: Direct 32-byte key (no PBKDF2 - assumes secure key management)
- **Nonce**: Randomly generated per encryption operation

### Key Storage
- Private keys are **never stored unencrypted**
- Public keys are stored in plaintext for verification
- All key operations are logged

### Access Control
- Encryption key must be secured outside the application
- Key directory should have restricted file permissions
- Legacy keys are backed up during migration

### Rotation Policy
- Rotate keys at least every 90 days
- Rotate immediately upon suspected compromise
- Maintain historical keys for audit trail verification

## Migration from Legacy Keys

The system automatically migrates unencrypted legacy keys:

1. Detects legacy key at `CANON_LEGACY_KEY_PATH`
2. Creates encrypted version as key index 1
3. Backs up legacy key with `.legacy_backup` extension
4. Stores encrypted keys in `CANON_KEY_DIR`

## Error Handling

### Common Errors

- **`InvalidEncryptionKey`**: Encryption key is not 32 bytes
- **`KeyNotFound`**: Requested key index doesn't exist
- **`Encryption`**: AES-GCM encryption/decryption failed
- **`InvalidKeyLength`**: Ed25519 key is not 32 bytes

### Recovery

If encryption key is lost:
1. **Historical verification will fail**
2. Generate new encryption key
3. Re-initialize key store (loses historical keys)
4. Update all Canon records with new signatures

## Testing

Run the key management test suite:

```bash
# Test all key functionality
cargo test keys::

# Test specific features
cargo test test_encrypted_key_storage
cargo test test_key_store_rotation
cargo test test_rotation_preserves_historical_verification
```

## Production Deployment

### Secure Setup

```bash
# Generate secure encryption key
ENCRYPTION_KEY=$(openssl rand -base64 32)

# Store in secure key management (e.g., AWS KMS, HashiCorp Vault)
echo "$ENCRYPTION_KEY" | vault kv put secret/sigil/encryption_key value=-

# Set production environment
export CANON_ENCRYPTION_KEY="$(vault kv get -field=value secret/sigil/encryption_key)"
export CANON_KEY_DIR="/opt/sigil/secure/keys"

# Set restrictive permissions
chmod 700 /opt/sigil/secure/keys
```

### Monitoring

Monitor key operations in logs:
- Key store initialization
- Key rotation events
- Legacy key migration
- Encryption/decryption errors

The system logs all key lifecycle events for audit purposes.
