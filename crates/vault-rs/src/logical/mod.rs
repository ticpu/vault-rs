pub mod commands;
pub mod data;
pub mod kv_commands;

/// The library's KV transport beside this crate's reporting verbs, so a caller
/// names one `kv` rather than picking a crate per verb.
pub mod kv {
    pub use vault_session::kv::*;

    pub use super::kv_commands::*;
}
