use thiserror::Error;

#[derive(Error, Debug)]
pub enum VaultCliError {
    #[error("Vault API error: {0}")]
    VaultApi(#[from] reqwest::Error),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Certificate parsing error: {0}")]
    CertParsing(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("YAML error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Certificate not found: {0}")]
    CertNotFound(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("UTF-8 conversion error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}

pub type Result<T> = std::result::Result<T, VaultCliError>;
