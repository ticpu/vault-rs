//! A session a linking program owns takes its token from the file it named.
//!
//! The proof is negative — that a token never left the process — so every test
//! mounts the operator's environment token as a mock expecting no request and
//! lets the `MockServer` verify it on drop.

use std::fs;
use std::path::PathBuf;
use vault_session::{Address, Session, SessionConfig};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// What an operator exported for their own admin session, which no
/// caller-owned session may reach.
const OPERATOR_TOKEN: &str = "s.operator-admin-token";
const CALLER_ENV: &str = "READ_SECRET_VAULT_TOKEN";
const CALLER_ENV_TOKEN: &str = "s.caller-env-token";
const FILE_TOKEN: &str = "s.caller-file-token";

const LOOKUP: &str = "/v1/auth/token/lookup-self";
const PROGRAM: &str = "read_secret";

/// `set_var` races every other thread's `getenv`, and the harness gives each
/// test its own thread. Before main is the only point where this binary has
/// one thread, so the variables are set there and never touched again.
#[cfg(target_os = "linux")]
#[ctor::ctor(unsafe)]
fn set_up_the_environment_these_tests_read() {
    test_confine::to_scratch_only(&test_confine::target_dir());

    std::env::set_var("VAULT_TOKEN", OPERATOR_TOKEN);
    std::env::set_var(CALLER_ENV, CALLER_ENV_TOKEN);
}

/// A session against the mock, resolving no address and no variable it was not
/// given.
async fn open(config: SessionConfig) -> Session {
    Session::open(config).await.expect("session")
}

/// A config addressed at the mock, with the token file under a named scratch
/// subdirectory.
fn config_at(server: &MockServer, name: &str) -> SessionConfig {
    SessionConfig::with_token_file(
        PROGRAM,
        token_at(name, FILE_TOKEN),
        Address::Explicit(server.uri()),
    )
}

fn token_at(name: &str, token: &str) -> PathBuf {
    let dir = test_confine::scratch_dir("caller-owned-session").join(name);
    // discard-ok: test scratch; the directory usually does not exist yet
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("scratch");

    let token_file = dir.join("token");
    fs::write(&token_file, token).expect("token");
    token_file
}

/// Accepts the token it is given and refuses to be asked about any other, so
/// an unexpected token is a failed expectation rather than a passing test.
async fn accepts(server: &MockServer, token: &str) {
    Mock::given(method("GET"))
        .and(path(LOOKUP))
        .and(header("X-Vault-Token", token))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "id": token }
        })))
        .expect(1)
        .mount(server)
        .await;
}

async fn never_asked_about(server: &MockServer, token: &str) {
    Mock::given(method("GET"))
        .and(path(LOOKUP))
        .and(header("X-Vault-Token", token))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(server)
        .await;
}

#[tokio::test]
async fn a_caller_owned_session_reads_its_file_and_not_the_environment() {
    let server = MockServer::start().await;
    accepts(&server, FILE_TOKEN).await;
    never_asked_about(&server, OPERATOR_TOKEN).await;

    let session = open(config_at(&server, "file-only")).await;

    assert_eq!(
        session.get_token().await.expect("the file token"),
        FILE_TOKEN
    );
}

/// A session may name its own variable; naming one is what it takes to read
/// any variable at all.
#[tokio::test]
async fn a_session_naming_a_variable_reads_that_one() {
    let server = MockServer::start().await;
    accepts(&server, CALLER_ENV_TOKEN).await;
    never_asked_about(&server, OPERATOR_TOKEN).await;

    let session = open(config_at(&server, "named-env").token_env(CALLER_ENV)).await;

    assert_eq!(
        session.get_token().await.expect("the caller's variable"),
        CALLER_ENV_TOKEN
    );
}

/// The other direction: a session that does name the operator's variable reads
/// it, so disabling that read for everyone is caught here. Only the tool's own
/// session names it.
#[tokio::test]
async fn a_session_naming_the_operator_s_variable_reads_it() {
    let server = MockServer::start().await;
    accepts(&server, OPERATOR_TOKEN).await;

    let session = open(config_at(&server, "operator-env").token_env("VAULT_TOKEN")).await;

    assert_eq!(
        session.get_token().await.expect("the environment token"),
        OPERATOR_TOKEN
    );
}

/// The confinement is a claim about the kernel, so it is checked rather than
/// trusted; a harmless probe catches one that stopped working before a real
/// write does.
#[test]
fn a_caller_owned_session_test_cannot_write_outside_its_scratch_directory() {
    let home = std::env::var("HOME").expect("a home to be kept out of");
    let outside = std::path::Path::new(&home).join(".vault-rs-should-never-appear");

    match fs::write(&outside, "this must not land") {
        Ok(()) => {
            // discard-ok: removing what should never have been written
            let _ = fs::remove_file(&outside);
            panic!(
                "wrote to {} — these tests are not confined",
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
