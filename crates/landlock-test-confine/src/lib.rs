//! Make the build directory the only place a test can write, using Landlock.
//!
//! Pointing every path at `target/` is a promise the test code makes to itself;
//! one forgotten environment variable and a test writes to the developer's real
//! home. This turns that promise into something the kernel refuses.
//!
//! ```no_run
//! # #[cfg(target_os = "linux")]
//! # fn confine() {
//! landlock_test_confine::to_scratch_only(&landlock_test_confine::target_dir());
//! # }
//! ```
//!
//! Applied per thread, since Landlock restricts the calling thread and what it
//! spawns but not its siblings, and the harness gives each test its own thread.
//! A kernel without it warns and continues: the tests are correct about their
//! paths regardless, and what is lost is the backstop. Pair it with a probe
//! asserting a write outside the boundary is refused, so a confinement that
//! stopped working is caught by something harmless.

use std::path::{Path, PathBuf};

/// The build directory this test binary was compiled into.
///
/// Resolved from the running executable rather than `CARGO_MANIFEST_DIR`: in a
/// workspace the manifest sits under `crates/`, while `target/` stays at the
/// root, so a path built from the manifest names a directory that does not
/// exist. Test binaries live at `<target>/<profile>/deps/`, and reading it back
/// from there also survives `CARGO_TARGET_DIR` pointing somewhere else
/// entirely, which the Arch package sets.
pub fn target_dir() -> PathBuf {
    let exe = std::env::current_exe().expect("a running test binary has a path");
    exe.ancestors()
        .nth(3)
        .unwrap_or_else(|| panic!("{} is not under <target>/<profile>/deps", exe.display()))
        .to_path_buf()
}

/// A scratch directory under the build directory, named for the caller.
pub fn scratch_dir(name: &str) -> PathBuf {
    target_dir().join(name)
}

/// Confine this thread, and anything it spawns, to reading anywhere and
/// writing only under `writable`.
pub fn to_scratch_only(writable: &Path) {
    thread_local! {
        static DONE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    DONE.with(|done| {
        if !done.replace(true) {
            apply(writable);
        }
    });
}

#[cfg(target_os = "linux")]
fn apply(writable: &Path) {
    use landlock::{
        path_beneath_rules, Access, AccessFs, LandlockStatus, Ruleset, RulesetAttr,
        RulesetCreatedAttr, RulesetStatus, ABI,
    };

    // The first version, because every later one is a superset and the crate
    // negotiates upward on its own. Naming a newer one only narrows the
    // kernels these tests can run on.
    let abi = ABI::V1;

    let restricted = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .and_then(|ruleset| ruleset.create())
        .and_then(|ruleset| {
            ruleset
                // Reading and running anything: these tests need the vault
                // binary, the system trust store and the crate's fixtures.
                .add_rules(path_beneath_rules(["/"], AccessFs::from_read(abi)))?
                // Writing only here.
                .add_rules(path_beneath_rules([writable], AccessFs::from_all(abi)))?
                // Discarding output is not a stray write.
                .add_rules(path_beneath_rules(["/dev/null"], AccessFs::from_all(abi)))
        })
        .and_then(|ruleset| ruleset.restrict_self());

    let status = match restricted {
        Ok(status) => status,
        Err(e) => return unconfined(writable, &format!("{e}")),
    };

    match (&status.ruleset, &status.landlock) {
        (RulesetStatus::FullyEnforced, _) => {}
        // The kernel's own answer, which distinguishes "not built in" from
        // "built in and switched off" — different things to go and fix.
        (_, LandlockStatus::NotImplemented) => {
            unconfined(writable, "this kernel has no Landlock support")
        }
        (_, LandlockStatus::NotEnabled) => unconfined(
            writable,
            "Landlock is built into this kernel but not enabled",
        ),
        (partial, _) => unconfined(writable, &format!("only {partial:?}")),
    }
}

#[cfg(not(target_os = "linux"))]
fn apply(writable: &Path) {
    unconfined(writable, "this platform has no Landlock");
}

fn unconfined(writable: &Path, why: &str) {
    eprintln!(
        "warning: not confined to {} ({why}); a stray write outside it would not be refused",
        writable.display()
    );
}
