use crate::cert::serial::SerialNumberParseError;
use thiserror::Error;

/// Variants carrying a `#[from]` source do NOT repeat it in their message:
/// the source is printed by whoever walks the chain, and including it here
/// too makes every such error render its cause twice.
#[derive(Error, Debug)]
pub enum VaultCliError {
    #[error("Vault API error")]
    VaultApi(#[from] reqwest::Error),

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

pub type Result<T> = std::result::Result<T, VaultCliError>;
