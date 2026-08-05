//! A throwaway Vault and a throwaway home, for tests that need a real server.
//!
//! Everything these tests touch is scratch: the dev server holds nothing that
//! outlives the test, and the local store, token and cache are pointed at a
//! directory under `target/`. That is the point rather than tidiness — these
//! commands mint keys, destroy secret versions and revoke tokens, and against
//! a real Vault or a real store any of them is a bad afternoon.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

/// The dev server's root token. Fixed, because the server is thrown away with
/// the test and nothing else can reach it.
const ROOT_TOKEN: &str = "root-token-for-tests";

const READY_TIMEOUT: Duration = Duration::from_secs(20);

/// How many dev servers may exist at once.
///
/// The tests are independent and would happily start one each, but a dev
/// server is not a cheap object and a machine asked for a dozen at once starts
/// refusing to bring them up — which surfaces as a readiness timeout that
/// looks exactly like a broken test. Bounding it keeps a failure here meaning
/// what it says.
const CONCURRENT_SERVERS: usize = 4;

static SERVERS_RUNNING: Mutex<usize> = Mutex::new(0);
static SERVER_FINISHED: Condvar = Condvar::new();

/// Held for as long as one server lives.
struct Slot;

impl Slot {
    fn take() -> Self {
        let mut running = SERVERS_RUNNING.lock().expect("server slots");
        while *running >= CONCURRENT_SERVERS {
            running = SERVER_FINISHED.wait(running).expect("server slots");
        }
        *running += 1;
        Slot
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut running = SERVERS_RUNNING.lock().expect("server slots");
        *running = running.saturating_sub(1);
        SERVER_FINISHED.notify_one();
    }
}

pub struct DevVault {
    _slot: Slot,
    server: Child,
    pub addr: String,
    home: PathBuf,
    log: PathBuf,
}

impl DevVault {
    /// Start a dev server and point a scratch home at it.
    ///
    /// A missing `vault` binary fails rather than skipping: a suite that
    /// quietly does not run reads exactly like one that passed.
    pub fn start(name: &str) -> Self {
        if which_vault().is_none() {
            panic!(
                "the integration tests need the `vault` binary on PATH.\n\
                 Install it, or set VAULT_RS_NO_INTEGRATION=1 to skip them knowingly."
            );
        }

        let slot = Slot::take();
        let home = scratch(name);
        let log = home.join("vault-server.log");
        let port = next_port();
        let addr = format!("http://127.0.0.1:{port}");

        let logfile = std::fs::File::create(&log).expect("server log");
        let server = Command::new("vault")
            .args([
                "server",
                "-dev",
                &format!("-dev-root-token-id={ROOT_TOKEN}"),
                &format!("-dev-listen-address=127.0.0.1:{port}"),
            ])
            // The server writes its root token to $HOME. Left pointing at the
            // real one, every server here overwrites the operator's own token
            // file, and two starting together race to rename it — the loser
            // exits, which arrives as a readiness timeout naming nothing.
            .env("HOME", &home)
            .stdout(Stdio::from(logfile.try_clone().expect("log handle")))
            .stderr(Stdio::from(logfile))
            .spawn()
            .expect("starting vault server -dev");

        let mut vault = Self {
            _slot: slot,
            server,
            addr,
            home,
            log,
        };
        vault.wait_until_serving();
        vault
    }

    /// Run vault-rs against this server, with the scratch home in place of the
    /// real one.
    pub fn run(&self, args: &[&str]) -> Output {
        let output = Command::new(env!("CARGO_BIN_EXE_vault-rs"))
            .args(args)
            .env("VAULT_ADDR", &self.addr)
            .env("VAULT_TOKEN", ROOT_TOKEN)
            .env("XDG_DATA_HOME", self.home.join("data"))
            .env("XDG_STATE_HOME", self.home.join("state"))
            .env("XDG_CONFIG_HOME", self.home.join("config"))
            .env("XDG_RUNTIME_DIR", self.home.join("run"))
            .env("HOME", &self.home)
            .output()
            .expect("running vault-rs");

        Output {
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            invocation: args.join(" "),
        }
    }

    /// Run vault-rs with something on stdin, for the value spellings that read
    /// from it.
    pub fn run_with_stdin(&self, args: &[&str], stdin: &str) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_vault-rs"))
            .args(args)
            .env("VAULT_ADDR", &self.addr)
            .env("VAULT_TOKEN", ROOT_TOKEN)
            .env("XDG_DATA_HOME", self.home.join("data"))
            .env("XDG_STATE_HOME", self.home.join("state"))
            .env("XDG_CONFIG_HOME", self.home.join("config"))
            .env("XDG_RUNTIME_DIR", self.home.join("run"))
            .env("HOME", &self.home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("running vault-rs");

        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(stdin.as_bytes())
            .expect("writing stdin");

        let output = child.wait_with_output().expect("waiting for vault-rs");
        Output {
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            invocation: args.join(" "),
        }
    }

    /// Enable a secrets engine directly, so a test can name the layout it
    /// needs rather than depending on what `-dev` happens to mount.
    pub fn enable(&self, kind: &str, at: &str) {
        let done = self.run(&["secrets", "enable", &format!("-path={at}"), kind]);
        assert!(
            done.code == Some(0),
            "enabling {kind} at {at} failed: {}",
            done.report()
        );
    }

    pub fn scratch_path(&self, name: &str) -> PathBuf {
        self.home.join(name)
    }

    fn wait_until_serving(&mut self) {
        let deadline = Instant::now() + READY_TIMEOUT;
        let mut last = None;
        while Instant::now() < deadline {
            let attempt = self.run(&["status"]);
            if attempt.code == Some(0) {
                return;
            }
            last = Some(attempt);
            std::thread::sleep(Duration::from_millis(200));
        }

        // Both halves of why: what the server said about coming up, and what
        // the last attempt to reach it got back. A bare timeout says only that
        // something did not happen.
        let whole_log = std::fs::read_to_string(&self.log).unwrap_or_default();
        // The tail: a dev server's banner is long and the reason it stopped is
        // at the end.
        let log: Vec<&str> = whole_log.lines().rev().take(15).collect();
        let log = log.into_iter().rev().collect::<Vec<_>>().join("\n");
        let attempt = last.map(|a| a.report()).unwrap_or_default();
        let child = match self.server.try_wait() {
            Ok(Some(status)) => format!("the server process exited: {status}"),
            Ok(None) => "the server process is still running".to_string(),
            Err(e) => format!("could not check the server process: {e}"),
        };
        panic!(
            "vault server -dev never became ready at {}\n{child}\n--- last attempt\n{attempt}\n--- server log\n{log}",
            self.addr
        );
    }
}

impl Drop for DevVault {
    fn drop(&mut self) {
        // discard-ok: the server is being torn down; a kill that fails because
        // it already exited is the outcome wanted either way
        let _ = self.server.kill();
        let _ = self.server.wait();
    }
}

pub struct Output {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    invocation: String,
}

impl Output {
    /// Everything about a run, for an assertion that failed to explain itself
    /// with.
    pub fn report(&self) -> String {
        format!(
            "`vault-rs {}` exited {:?}\n--- stdout\n{}--- stderr\n{}",
            self.invocation, self.code, self.stdout, self.stderr
        )
    }

    pub fn succeeded(&self) -> &Self {
        assert_eq!(self.code, Some(0), "{}", self.report());
        self
    }

    pub fn failed_with(&self, code: i32) -> &Self {
        assert_eq!(self.code, Some(code), "{}", self.report());
        self
    }

    pub fn stdout_has(&self, needle: &str) -> &Self {
        assert!(self.stdout.contains(needle), "{}", self.report());
        self
    }

    pub fn stderr_has(&self, needle: &str) -> &Self {
        assert!(self.stderr.contains(needle), "{}", self.report());
        self
    }

    pub fn stdout_lacks(&self, needle: &str) -> &Self {
        assert!(!self.stdout.contains(needle), "{}", self.report());
        self
    }

    pub fn stderr_lacks(&self, needle: &str) -> &Self {
        assert!(!self.stderr.contains(needle), "{}", self.report());
        self
    }
}

/// Whether these tests should run at all. Skipping is opt-in and says so, so
/// nobody reads a green suite as coverage it did not have.
pub fn skipped() -> bool {
    match std::env::var("VAULT_RS_NO_INTEGRATION") {
        Ok(value) if !value.is_empty() && value != "0" => {
            eprintln!("VAULT_RS_NO_INTEGRATION is set: not exercising a real Vault");
            true
        }
        // discard-ok: unset is the ordinary case, which runs the tests
        _ => false,
    }
}

fn which_vault() -> Option<PathBuf> {
    // discard-ok: an absent binary is what the caller is asking about
    which::which("vault").ok()
}

/// A port no other test in this process will ask for.
///
/// Not an OS-assigned one: asking the kernel for a free port hands back a
/// number that is free again the moment the probe socket closes, so two tests
/// starting together get the same answer and the second server fails to bind.
/// Counting instead makes the tests disjoint among themselves; the base is
/// derived from the process so two runs at once do not overlap either.
///
/// Two apart, because a dev server also binds the next port up for its cluster
/// address: consecutive servers would have the second one's API port land on
/// the first one's cluster port.
fn next_port() -> u16 {
    static NEXT: AtomicU16 = AtomicU16::new(0);

    let base = 20_000 + (std::process::id() as u16 % 20_000);
    base.wrapping_add(NEXT.fetch_add(2, Ordering::Relaxed))
}

fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/target/integration")).join(name);
    // discard-ok: test scratch; the directory usually does not exist yet
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch home");
    dir
}
