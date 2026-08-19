//! Where this tool keeps what it stores between runs.
//!
//! Separate from the session's own directory, which the library owns because a
//! linking program needs it and has no business acquiring a certificate store
//! along with it.

use crate::utils::errors::Result;
use crate::utils::PROGRAM_NAME;
use std::path::PathBuf;
use vault_session::Error;

pub struct CliPaths;

impl CliPaths {
    /// ~/.local/share/vault-rs/
    pub fn data_dir() -> Result<PathBuf> {
        Ok(dirs::data_local_dir()
            .map(|dir| dir.join(PROGRAM_NAME))
            .ok_or_else(|| Error::Paths("Cannot determine local data directory".to_string()))?)
    }

    /// ~/.config/vault-rs/
    pub fn config_dir() -> Result<PathBuf> {
        Ok(dirs::config_dir()
            .map(|dir| dir.join(PROGRAM_NAME))
            .ok_or_else(|| Error::Paths("Cannot determine config directory".to_string()))?)
    }

    /// ~/.local/share/vault-rs/secrets/
    pub fn secrets_dir() -> Result<PathBuf> {
        Ok(Self::data_dir()?.join("secrets"))
    }

    /// ~/.local/share/vault-rs/cache/
    pub fn cache_dir() -> Result<PathBuf> {
        Ok(Self::data_dir()?.join("cache"))
    }

    /// ~/.local/share/vault-rs/cache/serials/
    pub fn serial_cache_dir() -> Result<PathBuf> {
        Ok(Self::cache_dir()?.join("serials"))
    }

    /// ~/.local/share/vault-rs/cache/pki/
    pub fn pki_cache_dir() -> Result<PathBuf> {
        Ok(Self::cache_dir()?.join("pki"))
    }

    /// ~/.local/share/vault-rs/cache/certs/
    pub fn cert_cache() -> Result<PathBuf> {
        Ok(Self::cache_dir()?.join("certs"))
    }

    /// Ensure all necessary directories exist
    pub fn ensure_all_dirs() -> Result<()> {
        vault_session::paths::ensure_owner_only_dir(&Self::data_dir()?)?;
        vault_session::paths::ensure_owner_only_dir(&Self::config_dir()?)?;
        vault_session::paths::ensure_owner_only_dir(&vault_session::paths::runtime_dir(
            crate::utils::PROGRAM_NAME,
        )?)?;
        vault_session::paths::ensure_owner_only_dir(&Self::secrets_dir()?)?;
        vault_session::paths::ensure_owner_only_dir(&Self::cache_dir()?)?;
        vault_session::paths::ensure_owner_only_dir(&Self::serial_cache_dir()?)?;
        vault_session::paths::ensure_owner_only_dir(&Self::pki_cache_dir()?)?;
        vault_session::paths::ensure_owner_only_dir(&Self::cert_cache()?)?;
        Ok(())
    }
}
