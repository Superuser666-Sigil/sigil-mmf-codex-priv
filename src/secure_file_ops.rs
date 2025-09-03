//! Secure file operations with path validation and integrity verification
//!
//! This module implements secure file system operations as specified in Phase 2.8
//! of the security audit plan.

use crate::errors::SigilError;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

/// Secure file operations with validation and integrity checks
pub struct SecureFileOperations {
    allowed_paths: Vec<PathBuf>,
    max_file_size: usize,
    allowed_extensions: Vec<String>,
}

impl SecureFileOperations {
    /// Create a new secure file operations instance
    pub fn new(allowed_paths: Vec<String>, max_file_size: usize) -> Result<Self, SigilError> {
        let mut validated_paths = Vec::new();

        for path_str in allowed_paths {
            let path = PathBuf::from(path_str);
            if !path.exists() {
                return Err(SigilError::validation(
                    "allowed_paths",
                    format!("Path does not exist: {}", path.display()),
                ));
            }
            validated_paths.push(path);
        }

        Ok(SecureFileOperations {
            allowed_paths: validated_paths,
            max_file_size,
            allowed_extensions: vec![
                "json".to_string(),
                "toml".to_string(),
                "txt".to_string(),
                "log".to_string(),
                "dat".to_string(),
                "bin".to_string(),
            ],
        })
    }

    /// Validate a file path for security
    pub fn validate_path(&self, path: &Path) -> Result<(), SigilError> {
        let path_str = path.to_string_lossy();

        // Check for path traversal attempts
        if path_str.contains("..") || path_str.contains("~") {
            return Err(SigilError::validation(
                "path",
                "Path traversal attempt detected",
            ));
        }

        // Check if path is within allowed directories
        let is_allowed = self
            .allowed_paths
            .iter()
            .any(|allowed| path.starts_with(allowed));

        if !is_allowed {
            return Err(SigilError::validation(
                "path",
                format!("Path {path_str} is not in allowed directories"),
            ));
        }

        // Check file extension if present
        if let Some(extension) = path.extension() {
            let ext_str = extension.to_string_lossy().to_lowercase();
            if !self.allowed_extensions.contains(&ext_str.to_string()) {
                return Err(SigilError::validation(
                    "path",
                    format!("File extension '{ext_str}' not allowed"),
                ));
            }
        }

        Ok(())
    }

    /// Read a file securely with validation
    pub fn read_file_secure(&self, path: &Path) -> Result<Vec<u8>, SigilError> {
        self.validate_path(path)?;

        let metadata =
            fs::metadata(path).map_err(|e| SigilError::io("getting file metadata", e))?;

        if metadata.len() > self.max_file_size as u64 {
            return Err(SigilError::validation("file", "File too large"));
        }

        fs::read(path).map_err(|e| SigilError::io("reading file", e))
    }

    /// Write a file securely with validation
    pub fn write_file_secure(&self, path: &Path, data: &[u8]) -> Result<(), SigilError> {
        self.validate_path(path)?;

        if data.len() > self.max_file_size {
            return Err(SigilError::validation("data", "Data too large"));
        }

        // Ensure parent directory exists and is within allowed paths
        if let Some(parent) = path.parent() {
            self.validate_path(parent)?;
            fs::create_dir_all(parent).map_err(|e| SigilError::io("creating directory", e))?;
        }

        fs::write(path, data).map_err(|e| SigilError::io("writing file", e))
    }

    /// Calculate SHA256 hash of a file
    pub fn calculate_file_hash(&self, path: &Path) -> Result<String, SigilError> {
        let data = self.read_file_secure(path)?;
        let mut hasher = Sha256::new();
        hasher.update(&data);
        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Verify file integrity against expected hash
    pub fn verify_file_integrity(
        &self,
        path: &Path,
        expected_hash: &str,
    ) -> Result<bool, SigilError> {
        let actual_hash = self.calculate_file_hash(path)?;
        Ok(actual_hash == expected_hash)
    }

    /// Get file metadata securely
    pub fn get_file_metadata(&self, path: &Path) -> Result<FileMetadata, SigilError> {
        self.validate_path(path)?;

        let metadata =
            fs::metadata(path).map_err(|e| SigilError::io("getting file metadata", e))?;

        let hash = self.calculate_file_hash(path)?;

        Ok(FileMetadata {
            path: path.to_path_buf(),
            size: metadata.len(),
            modified: metadata
                .modified()
                .map_err(|e| SigilError::io("getting modification time", e))?
                .into(),
            hash,
            permissions: metadata.permissions(),
        })
    }

    /// List files in a directory securely
    pub fn list_files_secure(&self, dir_path: &Path) -> Result<Vec<PathBuf>, SigilError> {
        self.validate_path(dir_path)?;

        if !dir_path.is_dir() {
            return Err(SigilError::validation("path", "Path is not a directory"));
        }

        let mut files = Vec::new();

        for entry in fs::read_dir(dir_path).map_err(|e| SigilError::io("reading directory", e))? {
            let entry = entry.map_err(|e| SigilError::io("reading directory entry", e))?;
            let path = entry.path();

            // Validate each file path
            if self.validate_path(&path).is_ok() {
                files.push(path);
            }
        }

        Ok(files)
    }

    /// Copy a file securely
    pub fn copy_file_secure(&self, src: &Path, dst: &Path) -> Result<(), SigilError> {
        self.validate_path(src)?;
        self.validate_path(dst)?;

        let data = self.read_file_secure(src)?;
        self.write_file_secure(dst, &data)
    }

    /// Move a file securely
    pub fn move_file_secure(&self, src: &Path, dst: &Path) -> Result<(), SigilError> {
        self.validate_path(src)?;
        self.validate_path(dst)?;

        fs::rename(src, dst).map_err(|e| SigilError::io("moving file", e))
    }

    /// Delete a file securely
    pub fn delete_file_secure(&self, path: &Path) -> Result<(), SigilError> {
        self.validate_path(path)?;

        fs::remove_file(path).map_err(|e| SigilError::io("deleting file", e))
    }

    /// Get statistics about the secure file operations
    pub fn get_stats(&self) -> FileOpsStats {
        FileOpsStats {
            allowed_paths: self.allowed_paths.len(),
            max_file_size: self.max_file_size,
            allowed_extensions: self.allowed_extensions.clone(),
        }
    }
}

/// File metadata structure
#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub path: PathBuf,
    pub size: u64,
    pub modified: chrono::DateTime<chrono::Utc>,
    pub hash: String,
    pub permissions: std::fs::Permissions,
}

/// File operations statistics
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileOpsStats {
    pub allowed_paths: usize,
    pub max_file_size: usize,
    pub allowed_extensions: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::tempdir;

    #[test]
    fn test_secure_file_ops_creation() {
        let temp_dir = tempdir().unwrap();
        let allowed_paths = vec![temp_dir.path().to_string_lossy().to_string()];

        let file_ops = SecureFileOperations::new(allowed_paths, 1024 * 1024);
        assert!(file_ops.is_ok());
    }

    #[test]
    fn test_path_validation() {
        let temp_dir = tempdir().unwrap();
        let allowed_paths = vec![temp_dir.path().to_string_lossy().to_string()];
        let file_ops = SecureFileOperations::new(allowed_paths, 1024).unwrap();

        // Valid path
        let valid_path = temp_dir.path().join("test.txt");
        assert!(file_ops.validate_path(&valid_path).is_ok());

        // Invalid path - traversal attempt
        let invalid_path = temp_dir.path().join("../../../etc/passwd");
        assert!(file_ops.validate_path(&invalid_path).is_err());
    }

    #[test]
    fn test_file_read_write() {
        let temp_dir = tempdir().unwrap();
        let allowed_paths = vec![temp_dir.path().to_string_lossy().to_string()];
        let file_ops = SecureFileOperations::new(allowed_paths, 1024).unwrap();

        let test_file = temp_dir.path().join("test.txt");
        let test_data = b"Hello, secure file operations!";

        // Write file
        assert!(file_ops.write_file_secure(&test_file, test_data).is_ok());

        // Read file
        let read_data = file_ops.read_file_secure(&test_file).unwrap();
        assert_eq!(read_data, test_data);

        // Calculate hash
        let hash = file_ops.calculate_file_hash(&test_file).unwrap();
        assert!(!hash.is_empty());

        // Verify integrity
        assert!(file_ops.verify_file_integrity(&test_file, &hash).unwrap());
    }

    #[test]
    fn test_file_size_limit() {
        let temp_dir = tempdir().unwrap();
        let allowed_paths = vec![temp_dir.path().to_string_lossy().to_string()];
        let file_ops = SecureFileOperations::new(allowed_paths, 10).unwrap(); // 10 byte limit

        let test_file = temp_dir.path().join("test.txt");
        let large_data = b"This is larger than 10 bytes";

        // Should fail due to size limit
        assert!(file_ops.write_file_secure(&test_file, large_data).is_err());
    }
}
