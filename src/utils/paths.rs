use crate::utils::errors::{Result, VaultCliError};
use crate::utils::PROGRAM_NAME;
use dirs;
use std::fs;
use std::path::{Path, PathBuf};

pub struct VaultCliPaths;

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

    /// Get the runtime directory: `$XDG_RUNTIME_DIR/vault-rs/`, falling back to
    /// the state directory when the session offers no runtime one.
    ///
    /// This holds the authentication token; see docs/design-rationale.md,
    /// "A private persistent directory over a shared volatile one".
    pub fn runtime_dir() -> Result<PathBuf> {
        if let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") {
            return Ok(PathBuf::from(runtime_dir).join(PROGRAM_NAME));
        }

        dirs::state_dir()
            .map(|dir| dir.join(PROGRAM_NAME))
            .ok_or_else(|| {
                VaultCliError::Config(
                    "XDG_RUNTIME_DIR is unset and no state directory could be determined. \
                     The authentication token goes in one of those two or nowhere; set \
                     XDG_RUNTIME_DIR or XDG_STATE_HOME."
                        .to_string(),
                )
            })
    }

    /// Get the secrets storage directory: ~/.local/share/vault-rs/secrets/
    pub fn secrets_dir() -> Result<PathBuf> {
        Ok(Self::data_dir()?.join("secrets"))
    }

    /// Get the cache directory: ~/.local/share/vault-rs/cache/
    pub fn cache_dir() -> Result<PathBuf> {
        Ok(Self::data_dir()?.join("cache"))
    }

    /// Get the path for a specific certificate's storage directory (with serial)
    pub fn cert_storage_dir(pki_mount: &str, cn: &str, serial: &str) -> Result<PathBuf> {
        Ok(Self::secrets_dir()?.join(pki_mount).join(cn).join(serial))
    }

    /// Get the path for a certificate CN directory (without serial, for listing)
    pub fn cert_cn_dir(pki_mount: &str, cn: &str) -> Result<PathBuf> {
        Ok(Self::secrets_dir()?.join(pki_mount).join(cn))
    }

    /// Get the token file path: $XDG_RUNTIME_DIR/vault-rs/token
    pub fn vault_token() -> Result<PathBuf> {
        Ok(Self::runtime_dir()?.join("token"))
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

    /// Ensure a directory exists and is reachable only by its owner.
    ///
    /// The mode is checked on every call, not only on creation: a directory
    /// left behind by an earlier version, or created by someone else first,
    /// is exactly the case the 0600 file mode does not cover.
    pub fn ensure_dir_exists(path: &PathBuf) -> Result<()> {
        // `create_dir_all` applies the umask, so a directory we just made is
        // usually 0755 and tightening it is routine, not worth reporting.
        // Finding a pre-existing one too open is the case worth a warning.
        let existed = path.exists();
        if !existed {
            fs::create_dir_all(path)?;
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(path)?.permissions();
            let mode = perms.mode() & 0o777;
            if mode & 0o077 != 0 {
                if existed {
                    tracing::warn!("Tightening {} from mode {mode:04o} to 0700", path.display());
                } else {
                    tracing::debug!("Created {} as 0700", path.display());
                }
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/target/paths-tests")).join(name);
        // discard-ok: test scratch; the directory usually does not exist yet
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn mode_of(path: &PathBuf) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn a_new_directory_is_owner_only() {
        let dir = scratch("new");
        VaultCliPaths::ensure_dir_exists(&dir).unwrap();
        assert_eq!(mode_of(&dir), 0o700);
    }

    /// The token directory may already exist from an earlier version, or have
    /// been created by somebody else first. Only checking on creation leaves
    /// both cases readable.
    #[test]
    fn an_existing_permissive_directory_is_tightened() {
        let dir = scratch("permissive");
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();

        VaultCliPaths::ensure_dir_exists(&dir).unwrap();
        assert_eq!(mode_of(&dir), 0o700);
    }
}

/// Set restrictive permissions (600) on a file for secure storage
pub fn set_secure_file_permissions<P: AsRef<Path>>(path: P) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&path, perms)?;
    }
    Ok(())
}
