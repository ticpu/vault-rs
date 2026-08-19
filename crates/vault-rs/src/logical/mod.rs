pub mod commands;
pub mod data;
pub mod kv_commands;

/// The library's read verbs alongside the CLI's write and version verbs, so
/// `crate::logical::kv::put` resolves the way it always has even though the
/// two halves now live in different crates.
pub mod kv {
    pub use vault_session::logical::kv::*;

    pub use super::kv_commands::*;
}
