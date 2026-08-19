pub mod dns_discovery;
pub mod errors;
pub mod paths;

pub const PROGRAM_NAME: &str = "vault-rs";

pub use dns_discovery::*;
pub use errors::*;
pub use paths::*;
