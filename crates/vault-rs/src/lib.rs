//! Internal to the `vault-rs` binary. This is not a supported library API and
//! carries no stability guarantee: it exists so the binary's tests and command
//! handlers can share code. A program linking Vault support wants
//! [`vault-session`](https://docs.rs/vault-session) instead.

#[doc(hidden)]
pub mod cache;
#[doc(hidden)]
pub mod cert;
#[doc(hidden)]
pub mod cli;
#[doc(hidden)]
pub mod config;
#[doc(hidden)]
pub mod crypto;
#[doc(hidden)]
pub mod logical;
#[doc(hidden)]
pub mod policy;
#[doc(hidden)]
pub mod secrets;
#[doc(hidden)]
pub mod server;
#[doc(hidden)]
pub mod session;
#[doc(hidden)]
pub mod storage;
#[doc(hidden)]
pub mod utils;
#[doc(hidden)]
pub mod vault;

#[doc(hidden)]
pub use cert::{CertificateCache, CertificateParser, CertificateService};
#[doc(hidden)]
pub use cli::{args, commands};
#[doc(hidden)]
pub use crypto::encryption;
#[doc(hidden)]
pub use storage::local;
#[doc(hidden)]
pub use utils::{errors, paths};
#[doc(hidden)]
pub use vault::client;

/// Confine the unit tests to the build directory, before the harness starts a
/// single test so that every test thread inherits it.
#[cfg(all(test, target_os = "linux"))]
mod confinement {
    // `unsafe` because a constructor runs before main, where the runtime is not
    // yet up; this touches only the kernel and a thread-local.
    #[ctor::ctor(unsafe)]
    fn confine_to_the_build_directory() {
        test_confine::to_scratch_only(&test_confine::target_dir());
    }

    /// The confinement is a claim about the kernel, so it is checked rather
    /// than trusted. This wrote to a real home before it was in place: a store
    /// resolving where its key lives reached the operator's own data directory
    /// with no test helper anywhere in front of it.
    #[test]
    fn the_unit_tests_cannot_write_outside_the_build_directory() {
        let inside = test_confine::target_dir().join("confinement-probe");
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
