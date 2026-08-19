//! Address discovery, login, token handling and KV reads against HashiCorp
//! Vault, for a program that links them.
//!
//! The session is the caller's, not the machine's. Nothing here reads an
//! environment variable, a file or a directory the caller did not name, so a
//! linking program never inherits the operator's own Vault session by
//! accident: the address is an [`Address`] passed to [`SessionConfig`], the
//! token lives under the program's own name, and a variable is read only where
//! [`SessionConfig::token_env`] names one.
//!
//! Nothing here prints, prompts, opens a browser or exits. An OIDC login hands
//! its authorization URL to a [`LoginPresenter`] the caller supplies, and every
//! failure is a returned [`Error`] carrying its source.
//!
//! ```no_run
//! use vault_session::{kv, Address, Session, SessionConfig, VaultClient};
//!
//! # async fn run() -> Result<(), vault_session::Error> {
//! let config = SessionConfig::for_program("my-program", Address::EnvThenSrv)?;
//! let session = Session::open(config).await?;
//!
//! let client = VaultClient::for_session(&session).await?;
//! let secret = kv::read_secret(&client, Some("secret"), "app/config", None).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # TLS backend
//!
//! `rustls-aws-lc-rs` is the default. To let the process install its own
//! rustls `CryptoProvider`, turn the default off — selecting the feature
//! without doing so compiles both backends in:
//!
//! ```toml
//! vault-session = { version = "0.4", default-features = false, features = ["rustls-ring"] }
//! ```
//!
//! Unix only: the token file is created with an explicit mode.

#[cfg(not(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring")))]
compile_error!(
    "select a TLS backend: `rustls-aws-lc-rs`, or `rustls-ring` where the process installs its \
     own rustls provider. Selecting neither leaves this crate without a TLS implementation to \
     reach Vault over."
);

pub mod client;
pub mod discovery;
pub mod error;
pub mod kv;
pub mod mounts;
pub mod oidc;
pub mod paths;
pub mod session;
mod transport;
pub mod verify;

pub use client::{Capabilities, HealthStatus, KvLayout, MountLayout, VaultClient};
pub use discovery::Address;
pub use error::{Error, Result};
pub use mounts::VisibleMounts;
pub use oidc::Redirect;
pub use session::{LoginPresenter, LogoutOutcome, OidcLogin, Session, SessionConfig, TokenState};
pub use verify::{verify, Expectation, Finding};

/// Confine the unit tests to the build directory.
///
/// The restriction goes in before the harness starts a single test and every
/// test thread inherits it: the write this exists to refuse came from code with
/// no test helper in front of it.
#[cfg(all(test, target_os = "linux"))]
mod confinement {
    // `unsafe` because a constructor runs before main, where the runtime is not
    // yet up; this touches only the kernel and a thread-local.
    #[ctor::ctor(unsafe)]
    fn confine_to_the_build_directory() {
        landlock_test_confine::to_scratch_only(&landlock_test_confine::target_dir());
    }

    /// The confinement is a claim about the kernel, so it is checked rather
    /// than trusted. This wrote to a real home before it was in place: a store
    /// resolving where its key lives reached the operator's own data directory
    /// with no test helper anywhere in front of it.
    #[test]
    fn the_unit_tests_cannot_write_outside_the_build_directory() {
        let inside = landlock_test_confine::target_dir().join("confinement-probe");
        std::fs::write(&inside, "scratch").expect("writing inside the build directory");
        // discard-ok: tidying the probe; the assertions below are the report
        let _ = std::fs::remove_file(&inside);

        let home = std::env::var("HOME").expect("a home to be kept out of");
        for outside in [
            std::path::Path::new(&home).join(".local/share/vault-rs/key-mount.yaml"),
            std::path::Path::new(&home).join(".vault-rs-should-never-appear"),
        ] {
            match std::fs::write(&outside, "this must not land") {
                Ok(()) => {
                    // discard-ok: removing what should never have been written
                    let _ = std::fs::remove_file(&outside);
                    panic!(
                        "wrote to {} — the unit tests are not confined, so a path resolved from \
                         the real environment reaches a real store",
                        outside.display()
                    );
                }
                Err(e) => assert_eq!(
                    e.kind(),
                    std::io::ErrorKind::PermissionDenied,
                    "{} was refused for the wrong reason: {e}",
                    outside.display()
                ),
            }
        }
    }
}
