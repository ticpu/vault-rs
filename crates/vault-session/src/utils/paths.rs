use crate::utils::errors::{Error, Result};
use crate::utils::PROGRAM_NAME;
use dirs;
use std::fs;
use std::path::{Path, PathBuf};

pub struct VaultCliPaths;

impl VaultCliPaths {
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
                Error::Paths(
                    "XDG_RUNTIME_DIR is unset and no state directory could be determined. \
                     The authentication token goes in one of those two or nowhere; set \
                     XDG_RUNTIME_DIR or XDG_STATE_HOME."
                        .to_string(),
                )
            })
    }

    /// Get the token file path: $XDG_RUNTIME_DIR/vault-rs/token
    pub fn vault_token() -> Result<PathBuf> {
        Ok(Self::runtime_dir()?.join("token"))
    }

    /// Create a directory owner-only, leaving one that is already there alone.
    ///
    /// For a path this tool was handed rather than resolved: the mode of a
    /// directory somebody else owns is theirs to decide, and one too open to
    /// hold a token is reported so they can.
    pub fn create_owner_only_dir(path: &Path) -> Result<()> {
        // `create_dir_all` applies the umask, so a directory we just made is
        // usually 0755 and tightening it is routine, not worth reporting.
        if !path.exists() {
            fs::create_dir_all(path)?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(path)?.permissions();
                perms.set_mode(0o700);
                fs::set_permissions(path, perms)?;
                tracing::debug!("Created {} as 0700", path.display());
            }
            return Ok(());
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(path)?.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                tracing::warn!(
                    "{} is mode {mode:04o}; anything written there is reachable by others",
                    path.display()
                );
            }
        }
        Ok(())
    }

    /// Ensure a directory this tool owns exists and is reachable only by its
    /// owner.
    ///
    /// The mode is checked on every call, not only on creation: a directory
    /// left behind by an earlier version, or created by someone else first,
    /// is exactly the case the 0600 file mode does not cover.
    pub fn ensure_dir_exists(path: &Path) -> Result<()> {
        let existed = path.exists();
        Self::create_owner_only_dir(path)?;

        #[cfg(unix)]
        if existed {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(path)?.permissions();
            let mode = perms.mode() & 0o777;
            if mode & 0o077 != 0 {
                tracing::warn!("Tightening {} from mode {mode:04o} to 0700", path.display());
                perms.set_mode(0o700);
                fs::set_permissions(path, perms)?;
            }
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn scratch(name: &str) -> PathBuf {
        let dir = test_confine::scratch_dir("paths-tests").join(name);
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

    #[test]
    fn a_directory_created_for_a_caller_is_owner_only() {
        let dir = scratch("caller-new");
        VaultCliPaths::create_owner_only_dir(&dir).unwrap();
        assert_eq!(mode_of(&dir), 0o700);
    }

    /// A caller naming a token path under a directory it already keeps for
    /// other things is told the mode is loose, not silently given a new one.
    #[test]
    fn a_caller_s_own_directory_keeps_its_mode() {
        let dir = scratch("caller-existing");
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();

        VaultCliPaths::create_owner_only_dir(&dir).unwrap();
        assert_eq!(mode_of(&dir), 0o755);
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
