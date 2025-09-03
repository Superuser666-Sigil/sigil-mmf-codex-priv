//! Platform-specific optimizations for dependency reduction
//!
//! This module provides Linux-specific optimizations that can reduce
//! dependency bloat when deploying in Docker containers.

#[cfg(target_os = "linux")]
pub mod linux {
    use std::path::PathBuf;

    /// Get Linux-specific configuration directory
    pub fn get_config_dir() -> Option<PathBuf> {
        std::env::var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|_| std::env::var("HOME").map(|home| PathBuf::from(home).join(".config")))
            .ok()
    }

    /// Get Linux-specific data directory
    pub fn get_data_dir() -> Option<PathBuf> {
        std::env::var("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|_| std::env::var("HOME").map(|home| PathBuf::from(home).join(".local/share")))
            .ok()
    }

    /// Check if running in a container environment
    pub fn is_containerized() -> bool {
        std::path::Path::new("/.dockerenv").exists()
            || std::env::var("KUBERNETES_SERVICE_HOST").is_ok()
    }

    /// Get container-specific optimizations
    pub fn get_container_optimizations() -> Vec<&'static str> {
        vec![
            "disable_gui_features",
            "disable_windows_support",
            "optimize_for_linux",
            "use_linux_specific_apis",
        ]
    }
}

#[cfg(not(target_os = "linux"))]
pub mod linux {
    use std::path::PathBuf;

    /// Fallback for non-Linux platforms
    pub fn get_config_dir() -> Option<PathBuf> {
        None
    }

    /// Fallback for non-Linux platforms  
    pub fn get_data_dir() -> Option<PathBuf> {
        None
    }

    /// Fallback for non-Linux platforms
    pub fn is_containerized() -> bool {
        false
    }

    /// Fallback for non-Linux platforms
    pub fn get_container_optimizations() -> Vec<&'static str> {
        vec![]
    }
}

/// Platform-agnostic optimizations
pub mod common {
    use std::collections::HashMap;

    /// Get platform-specific feature flags
    pub fn get_platform_features() -> HashMap<&'static str, bool> {
        let mut features = HashMap::new();

        #[cfg(target_os = "linux")]
        {
            features.insert("linux_support", true);
            features.insert(
                "container_optimized",
                crate::platform_optimizations::linux::is_containerized(),
            );
        }

        #[cfg(target_os = "windows")]
        {
            features.insert("windows_support", true);
        }

        #[cfg(target_os = "macos")]
        {
            features.insert("macos_support", true);
        }

        features
    }

    /// Get recommended build features for current platform
    pub fn get_recommended_features() -> Vec<&'static str> {
        let mut features = vec!["security", "ml"];

        #[cfg(target_os = "linux")]
        {
            if crate::platform_optimizations::linux::is_containerized() {
                features.push("docker");
            } else {
                features.push("full");
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            features.push("full");
        }

        features
    }
}
