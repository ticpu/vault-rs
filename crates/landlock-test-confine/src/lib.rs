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
//!
//! A thread holding CAP_DAC_OVERRIDE or CAP_DAC_READ_SEARCH loses them first,
//! so tests running as root see file modes as any other account does.

use std::path::{Path, PathBuf};

/// The build directory this test binary was compiled into: cargo's build-dir,
/// or `<build-dir>/<triple>` under `--target`, the directory that holds
/// `CARGO_TARGET_TMPDIR`.
///
/// Resolved from the running executable rather than `CARGO_MANIFEST_DIR`: in a
/// workspace the manifest sits under `crates/`, while `target/` stays at the
/// root, so a path built from the manifest names a directory that does not
/// exist. Reading it back from the executable also follows `CARGO_TARGET_DIR`
/// and a separate build-dir, which the test process is not told about.
///
/// # Panics
///
/// When the executable is in neither `<root>/<profile>/deps/` nor
/// `<root>/<profile>/build/<pkg>/<hash>/out/`. A guess there would quietly
/// shrink or widen the writable root.
pub fn target_dir() -> PathBuf {
    let exe = std::env::current_exe().expect("a running test binary has a path");
    build_root(&exe)
        .unwrap_or_else(|| {
            panic!(
                "{} is under neither <root>/<profile>/deps nor \
                 <root>/<profile>/build/<pkg>/<hash>/out",
                exe.display()
            )
        })
        .to_path_buf()
}

/// The build root above a test executable, for the two layouts cargo has used.
fn build_root(exe: &Path) -> Option<&Path> {
    let named = |n: usize, name: &str| {
        exe.ancestors()
            .nth(n)
            .and_then(Path::file_name)
            .is_some_and(|found| found == name)
    };
    let depth = if named(1, "deps") {
        3
    } else if named(1, "out") && named(4, "build") {
        6
    } else {
        return None;
    };
    exe.ancestors().nth(depth)
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

    drop_dac_override();

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

/// Make file modes bind this thread as they bind any other account, so a test
/// running as root is refused a mode-000 open. CAP_FOWNER stays for cleanup.
#[cfg(target_os = "linux")]
fn drop_dac_override() {
    use rustix::thread::{capabilities, set_capabilities, set_no_new_privs, CapabilitySet};

    let dac = CapabilitySet::DAC_OVERRIDE | CapabilitySet::DAC_READ_SEARCH;
    let mut sets = match capabilities(None) {
        Ok(sets) => sets,
        Err(e) if rustix::process::geteuid().is_root() => {
            panic!("reading this thread's capabilities as root: {e}")
        }
        Err(e) => {
            eprintln!(
                "warning: could not read this thread's capabilities ({e}); \
                 a DAC override it holds would not be dropped"
            );
            return;
        }
    };

    let held = (sets.effective | sets.permitted | sets.inheritable) & dac;
    if !held.is_empty() {
        sets.effective.remove(dac);
        sets.permitted.remove(dac);
        sets.inheritable.remove(dac);
        if let Err(e) = set_capabilities(None, sets) {
            panic!("dropping {held:?} from this thread: {e}");
        }
    }

    // Without it a root execve refills permitted from the bounding set, which
    // is left alone. Landlock sets it too, but not on the paths that bail out.
    if let Err(e) = set_no_new_privs(true) {
        if held.is_empty() {
            eprintln!("warning: could not set no_new_privs ({e})");
        } else {
            panic!("setting no_new_privs after dropping {held:?}: {e}; a child run as root would regain it");
        }
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

#[cfg(test)]
mod tests {
    use super::build_root;
    use std::path::Path;

    #[test]
    fn the_deps_layout_resolves_to_the_build_dir() {
        let exe = Path::new("/w/target/release/deps/suite-0123abcd");
        assert_eq!(build_root(exe), Some(Path::new("/w/target")));
    }

    #[test]
    fn the_build_out_layout_resolves_to_the_build_dir() {
        let exe = Path::new("/w/target/release/build/my-pkg/0123abcd/out/suite-0123abcd");
        assert_eq!(build_root(exe), Some(Path::new("/w/target")));
    }

    #[test]
    fn a_target_triple_stays_part_of_the_root() {
        let deps = Path::new("/w/target/x86_64-unknown-linux-gnu/debug/deps/suite-0123abcd");
        let out = Path::new(
            "/w/target/x86_64-unknown-linux-gnu/debug/build/my-pkg/0123abcd/out/suite-0123abcd",
        );
        let root = Some(Path::new("/w/target/x86_64-unknown-linux-gnu"));
        assert_eq!(build_root(deps), root);
        assert_eq!(build_root(out), root);
    }

    #[test]
    fn an_unrecognised_layout_has_no_root() {
        for exe in [
            "/w/target/release/suite-0123abcd",
            "/w/target/release/build/my-pkg/out/suite-0123abcd",
            "/w/target/release/elsewhere/my-pkg/0123abcd/out/suite-0123abcd",
            "/deps/suite",
        ] {
            assert_eq!(build_root(Path::new(exe)), None, "{exe}");
        }
    }
}
