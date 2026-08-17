#[cfg(feature = "cli")]
pub mod cert_utils;
pub mod dns_discovery;
pub mod errors;
pub mod output;
#[cfg(feature = "cli")]
pub mod partial;
pub mod paths;
#[cfg(feature = "cli")]
pub mod pem;
#[cfg(feature = "cli")]
pub mod prompt;
pub const PROGRAM_NAME: &str = "vault-rs";

#[cfg(feature = "cli")]
pub use cert_utils::*;
pub use dns_discovery::*;
pub use errors::*;
pub use output::*;
pub use paths::*;
#[cfg(feature = "cli")]
pub use pem::*;
#[cfg(feature = "cli")]
pub use prompt::*;
