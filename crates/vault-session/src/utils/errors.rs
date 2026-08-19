use thiserror::Error;

/// Variants carrying a source do NOT repeat it in their message: the source is
/// printed by whoever walks the chain, and including it here too makes every
/// such error render its cause twice.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// A refusal from Vault with the status it carried and the endpoint it was
    /// refused for. The status stays on the error because one code covers
    /// answers that differ per engine — an unwritten path and a withdrawn
    /// version arrive alike — and a caller left matching on message text cannot
    /// tell them apart. The path stays on it because one status also covers a
    /// path that is not routed and an identity that may not reach it.
    #[error("Vault returned {status} for '{path}'{}", render_errors(.errors))]
    Status {
        status: u16,
        path: String,
        errors: Vec<String>,
    },

    /// The request never reached an answer.
    #[error("could not reach Vault")]
    Transport(#[from] reqwest::Error),

    /// An answer that did not have the shape its endpoint promises.
    #[error("could not read Vault's answer for '{path}'")]
    Decode {
        path: String,
        #[source]
        source: serde_json::Error,
    },

    /// Finding the Vault address. The source is boxed because what fails here
    /// is a resolver or a cache file, and naming either type would put it in
    /// this crate's public API for an error nobody matches on.
    #[error("{doing}")]
    Discovery {
        doing: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Discovery ran and found nothing. Distinct from a discovery that failed:
    /// there is no cause to report, and the remedy is to name an address rather
    /// than to fix a resolver.
    #[error("{0}")]
    NoAddress(String),

    /// No directory to keep a session's files in.
    #[error("{0}")]
    Paths(String),

    /// Rendering a record the caller handed us.
    #[error("could not render a record as JSON")]
    Encode(#[from] serde_json::Error),

    /// The login did not produce a usable token.
    #[error("{0}")]
    Auth(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("could not read a file this session owns")]
    Io(#[from] std::io::Error),

    #[error("Vault answered with something that is not UTF-8")]
    Utf8(#[from] std::string::FromUtf8Error),
}

/// What the server said, appended only when it said anything.
fn render_errors(errors: &[String]) -> String {
    match errors.is_empty() {
        true => String::new(),
        false => format!(": {}", errors.join("; ")),
    }
}

impl Error {
    /// Build a refusal from a response body, lifting Vault's own `errors`
    /// array out of it when there is one.
    pub fn refusal(path: &str, status: u16, body: String) -> Self {
        let errors = match serde_json::from_str::<serde_json::Value>(&body) {
            Ok(envelope) => match envelope.get("errors").and_then(|e| e.as_array()) {
                Some(reported) => reported
                    .iter()
                    .filter_map(|e| e.as_str().map(str::to_string))
                    .collect(),
                None => vec![body],
            },
            // discard-ok: a body that is not JSON is still what the server said
            Err(_) if body.trim().is_empty() => Vec::new(),
            Err(_) => vec![body],
        };

        Self::Status {
            status,
            path: path.to_string(),
            errors,
        }
    }

    /// The status Vault answered with, where it answered at all.
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Status { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// Whether Vault answered that there is nothing at the path. What that
    /// means is the caller's to decide — engines use the one status for a path
    /// never written and for a version withdrawn.
    pub fn is_not_found(&self) -> bool {
        self.status() == Some(404)
    }

    /// Whether the token was refused the path. This is the answer to most
    /// "why can this program not read its own document" questions, and Vault
    /// gives it for a path that is not routed as readily as for one the policy
    /// does not reach.
    pub fn is_permission_denied(&self) -> bool {
        self.status() == Some(403)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
