pub mod cache;
pub mod cert;
pub mod cli;
pub mod config;
pub mod crypto;
pub mod logical;
pub mod policy;
pub mod secrets;
pub mod server;
pub mod session;
pub mod storage;
pub mod utils;
pub mod vault;

pub use cert::{CertificateCache, CertificateParser, CertificateService};
pub use cli::{args, commands};
pub use crypto::encryption;
pub use storage::local;
pub use utils::{errors, paths};
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
