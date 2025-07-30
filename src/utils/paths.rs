use crate::utils::errors::{Result, VaultCliError};
use dirs;
use std::fs;
use std::path::PathBuf;

pub struct VaultCliPaths;
const PROGRAM_NAME: &str = "vault-rs";

impl VaultCliPaths {
    /// Get the base data directory: ~/.local/share/vault-rs/
    pub fn data_dir() -> Result<PathBuf> {
        dirs::data_local_dir()
            .map(|dir| dir.join(PROGRAM_NAME))
            .ok_or_else(|| {
                VaultCliError::Config("Cannot determine local data directory".to_string())
            })
    }

    /// Get the config directory: ~/.config/vault-rs/
    pub fn config_dir() -> Result<PathBuf> {
        dirs::config_dir()
            .map(|dir| dir.join(PROGRAM_NAME))
            .ok_or_else(|| VaultCliError::Config("Cannot determine config directory".to_string()))
    }

    /// Get the runtime directory: $XDG_RUNTIME_DIR/vault-rs/
    pub fn runtime_dir() -> Result<PathBuf> {
        if let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") {
            Ok(PathBuf::from(runtime_dir).join(PROGRAM_NAME))
        } else {
            // Fallback to temp directory with user-specific path
            let user_id = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());
            Ok(PathBuf::from(format!("/tmp/{PROGRAM_NAME}-{user_id}")))
        }
    }

    /// Get the secrets storage directory: ~/.local/share/vault-rs/secrets/
    pub fn secrets_dir() -> Result<PathBuf> {
        Ok(Self::data_dir()?.join("secrets"))
    }

    /// Get the cache directory: ~/.local/share/vault-rs/cache/
    pub fn cache_dir() -> Result<PathBuf> {
        Ok(Self::data_dir()?.join("cache"))
    }

    /// Get the path for a specific certificate's storage directory
    pub fn cert_storage_dir(pki_mount: &str, cn: &str) -> Result<PathBuf> {
        Ok(Self::secrets_dir()?.join(pki_mount).join(cn))
    }

    /// Get the token file path: $XDG_RUNTIME_DIR/vault-rs/token
    pub fn vault_token() -> Result<PathBuf> {
        Ok(Self::runtime_dir()?.join("token"))
    }

    /// Get the audit log path: ~/.local/share/vault-rs/audit.log
    pub fn audit_log() -> Result<PathBuf> {
        Ok(Self::data_dir()?.join("audit.log"))
    }

    /// Get the master index path: ~/.local/share/vault-rs/cache/index.yaml.enc
    pub fn master_index() -> Result<PathBuf> {
        Ok(Self::cache_dir()?.join("index.yaml.enc"))
    }

    /// Get the serial cache directory: ~/.local/share/vault-rs/cache/serials/
    pub fn serial_cache_dir() -> Result<PathBuf> {
        Ok(Self::cache_dir()?.join("serials"))
    }

    /// Get the PKI cache directory: ~/.local/share/vault-rs/cache/pki/
    pub fn pki_cache_dir() -> Result<PathBuf> {
        Ok(Self::cache_dir()?.join("pki"))
    }

    /// Get the certificate cache directory: ~/.local/share/vault-rs/cache/certs/
    pub fn cert_cache() -> Result<PathBuf> {
        Ok(Self::cache_dir()?.join("certs"))
    }

    /// Ensure a directory exists with proper permissions
    pub fn ensure_dir_exists(path: &PathBuf) -> Result<()> {
        if !path.exists() {
            fs::create_dir_all(path)?;

            // Set restrictive permissions on data directories (700)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(path)?.permissions();
                perms.set_mode(0o700);
                fs::set_permissions(path, perms)?;
            }
        }
        Ok(())
    }

    /// Ensure all necessary directories exist
    pub fn ensure_all_dirs() -> Result<()> {
        Self::ensure_dir_exists(&Self::data_dir()?)?;
        Self::ensure_dir_exists(&Self::config_dir()?)?;
        Self::ensure_dir_exists(&Self::runtime_dir()?)?;
        Self::ensure_dir_exists(&Self::secrets_dir()?)?;
        Self::ensure_dir_exists(&Self::cache_dir()?)?;
        Self::ensure_dir_exists(&Self::serial_cache_dir()?)?;
        Self::ensure_dir_exists(&Self::pki_cache_dir()?)?;
        Self::ensure_dir_exists(&Self::cert_cache()?)?;
        Ok(())
    }
}
