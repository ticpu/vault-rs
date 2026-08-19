# landlock-test-confine

Make the build directory the only place a test can write, using
[Landlock](https://landlock.io/).

Pointing every path in a test at `target/` is a promise the test code makes to itself. One
forgotten environment variable and it writes to the developer's real home instead — which is how a
dev server in this workspace came to overwrite a real token file. This turns that promise into
something the kernel refuses.

```rust
#[cfg(all(test, target_os = "linux"))]
mod confinement {
    // A constructor runs before the harness starts a single test, so every
    // test thread inherits the restriction.
    #[ctor::ctor(unsafe)]
    fn confine() {
        landlock_test_confine::to_scratch_only(&landlock_test_confine::target_dir());
    }
}
```

Reading and executing stay allowed everywhere — tests need fixtures, the system trust store, and
whatever binaries they drive. Writing is allowed only under the path you pass, plus `/dev/null`.

`target_dir()` resolves from the running executable rather than `CARGO_MANIFEST_DIR`, so it is
correct in a workspace (where the manifest sits under `crates/` but `target/` does not) and follows
`CARGO_TARGET_DIR` when it is set.

## Per thread, not per process

Landlock restricts the calling thread and anything it goes on to spawn; sibling threads are
untouched unless the kernel offers process-wide enforcement, which is not something to depend on.
The test harness gives each test its own thread, so each confines itself before spawning anything.
`to_scratch_only` is idempotent per thread.

## When it cannot apply

A kernel without Landlock, or with it built in but switched off, gets a warning on stderr and the
tests run unconfined. The tests are correct about their paths either way; what is lost is the
backstop, and a confinement that quietly did not apply is worse than none. Pair it with a probe
that asserts a write outside the boundary is refused, so a confinement that stopped working is
caught by something harmless.

Non-Linux platforms warn and continue.

## License

MIT OR Apache-2.0.
