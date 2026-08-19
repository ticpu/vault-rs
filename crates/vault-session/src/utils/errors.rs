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

    /// A refusal from Vault with the status it carried. The status stays on the
    /// error because one code covers answers that differ per engine — an
    /// unwritten path and a withdrawn version arrive alike — and a caller left
    /// matching on message text cannot tell them apart.
    #[error("Vault returned {status} for '{path}'{}", render_errors(.errors))]
    VaultStatus {
        status: u16,
        path: String,
        errors: Vec<String>,
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

/// What the server said, appended only when it said anything.
fn render_errors(errors: &[String]) -> String {
    match errors.is_empty() {
        true => String::new(),
        false => format!(": {}", errors.join("; ")),
    }
}

impl VaultCliError {
    /// Whether Vault answered that there is nothing at the path. What that
    /// means is the caller's to decide — engines use the one status for a path
    /// never written and for a version withdrawn.
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::VaultStatus { status: 404, .. })
    }
}

pub type Result<T> = std::result::Result<T, VaultCliError>;
