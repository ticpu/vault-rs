// Make the scratch directory the only place these tests can write.
//
// The harness already points every path at `target/`, but that is a promise
// the code makes to itself: one forgotten environment variable and a test
// writes to the operator's real home, which is how a dev server came to
// overwrite a real token file. This turns the promise into something the
// kernel refuses rather than something the tests remember.
//
// Applied per thread, not once per process. Landlock restricts the calling
// thread and the children it goes on to spawn — sibling threads are untouched
// unless the kernel is new enough to offer process-wide enforcement, which is
// not something to depend on. The test harness gives each test its own thread,
// so each confines itself before spawning anything.
//
// Missing or partial support warns and continues. The tests are correct about
// their paths without it; what is lost is the backstop, and one that quietly
// did not apply is worse than none.
use std::path::Path;

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
