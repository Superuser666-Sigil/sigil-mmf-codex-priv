//! Comprehensive tests for Ed25519 key lifecycle management

use crate::keys::KeyManager;
use base64::Engine;
use rand;
use sha2::Digest;
use tempfile::TempDir;
use temp_env; 
