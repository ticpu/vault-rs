use crate::cert::serial::SerialNumberParseError;
use thiserror::Error;

/// Variants carrying a `#[from]` source do NOT repeat it in their message:
/// the source is printed by whoever walks the chain, and including it here
/// too makes every such error render its cause twice.
#[derive(Error, Debug)]
pub enum VaultCliError {
    /// Anything the session layer refused or could not do. Its own variants
    /// stay intact underneath, so a status and the endpoint it was refused for
    /// survive the trip up here.
    #[error(transparent)]
    Session(#[from] vault_session::Error),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Certificate parsing error: {0}")]
    CertParsing(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("IO error")]
    Io(#[from] std::io::Error),

    #[error("JSON error")]
    Json(#[from] serde_json::Error),

    #[error("YAML error")]
    Yaml(#[from] serde_yaml_ng::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Invalid Serial Number '{key}'")]
    SerialNumberParse {
        key: String,
        source: SerialNumberParseError,
    },

    #[error("Certificate not found: {0}")]
    CertNotFound(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Carries the whole report — every skipped subject and unread field — so
    /// the caller prints one message rather than reconstructing the set.
    #[error("Incomplete result: {0}")]
    IncompleteRead(String),

    #[error("UTF-8 conversion error")]
    Utf8(#[from] std::string::FromUtf8Error),
}

impl VaultCliError {
    /// Whether Vault answered that there is nothing at the path. What that
    /// means is the caller's to decide — engines use the one status for a path
    /// never written and for a version withdrawn.
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::Session(e) if e.is_not_found())
    }

    /// Whether the token was refused the path.
    pub fn is_permission_denied(&self) -> bool {
        matches!(self, Self::Session(e) if e.is_permission_denied())
    }
}

pub type Result<T> = std::result::Result<T, VaultCliError>;
