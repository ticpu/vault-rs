//! ACL policies over `sys/policies/acl`, so managing them does not need the
//! `vault` binary alongside this one.

pub mod commands;

pub use commands::handle_policy_commands;
