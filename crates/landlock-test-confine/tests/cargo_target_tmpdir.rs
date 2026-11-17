//! A consumer confined to `target_dir()` can write where cargo tells integration
//! tests to, `CARGO_TARGET_TMPDIR`, whichever executable layout cargo used.

use std::path::Path;

#[test]
fn cargo_target_tmpdir_is_writable_under_confinement() {
    let root = landlock_test_confine::target_dir();
    let tmp = Path::new(env!("CARGO_TARGET_TMPDIR"));
    assert!(
        tmp.starts_with(&root),
        "CARGO_TARGET_TMPDIR {} is outside target_dir() {}",
        tmp.display(),
        root.display()
    );

    landlock_test_confine::to_scratch_only(&root);
    let dir = tmp.join(format!("landlock-test-confine-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("creating a directory under CARGO_TARGET_TMPDIR");
    std::fs::write(dir.join("probe"), b"").expect("writing under CARGO_TARGET_TMPDIR");
    std::fs::remove_dir_all(&dir).expect("removing the probe directory");
}
