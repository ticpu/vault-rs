//! The loopback listener the identity provider redirects back to.
//!
//! One request is served and the listener stops. Anything the browser asks for
//! besides the callback path — a favicon, a speculative prefetch — is answered
//! and ignored, since answering it is what keeps the connection from being the
//! callback we are waiting for.

use crate::utils::errors::{Result, VaultCliError};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// The path the redirect URI names, and the only one that ends the wait.
const CALLBACK_PATH: &str = "/oidc/callback";

/// Long enough to reach a provider that wants a password and a second factor.
const WAIT: Duration = Duration::from_secs(120);

/// A request line longer than this is not a redirect from an identity provider.
const MAX_REQUEST_LINE: usize = 8192;

/// How long one connection has to send its request line.
const REQUEST_WAIT: Duration = Duration::from_secs(10);

/// Says only that the redirect arrived: whether the grant on it buys a token is
/// settled after this page is already served, and the terminal reports that.
const RECEIVED_PAGE: &str = "<!DOCTYPE html>
<html lang=\"en\">
<head><meta charset=\"utf-8\"><title>Response received</title></head>
<body><p>Response received. Close this window and return to the terminal.</p></body>
</html>
";

const REFUSED_PAGE: &str = "<!DOCTYPE html>
<html lang=\"en\">
<head><meta charset=\"utf-8\"><title>Sign-in refused</title></head>
<body><p>Sign-in refused. Close this window; the terminal says why.</p></body>
</html>
";

/// What the provider handed back, for the token exchange.
pub struct Callback {
    pub state: String,
    pub code: String,
    /// Set only by a flow that puts the identity token on the redirect's own
    /// query beside the code; the fragment an implicit flow uses never reaches
    /// a server.
    pub id_token: Option<String>,
}

/// Loopback sockets waiting for the redirect.
pub struct CallbackListener {
    sockets: Vec<TcpListener>,
    port: u16,
}

impl CallbackListener {
    /// Both loopback families, because the redirect URI names `localhost` and
    /// which family that resolves to is the browser's resolver's choice.
    /// Binding one of the two is enough to serve; failing both is not.
    pub async fn bind(port: u16) -> Result<Self> {
        if port == 0 {
            return Err(VaultCliError::InvalidInput(
                "The OIDC redirect port has to be one the role's allowed redirect URIs name, so \
                 it cannot be left to the kernel to pick."
                    .to_string(),
            ));
        }

        let mut sockets = Vec::new();
        let mut refusals = Vec::new();

        for (family, bound) in [
            (
                "127.0.0.1",
                TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await,
            ),
            (
                "[::1]",
                TcpListener::bind((Ipv6Addr::LOCALHOST, port)).await,
            ),
        ] {
            match bound {
                Ok(socket) => sockets.push(socket),
                Err(e) => {
                    tracing::warn!("Cannot listen on {family}:{port} for the OIDC redirect: {e}");
                    refusals.push(format!("{family}:{port}: {e}"));
                }
            }
        }

        if sockets.is_empty() {
            return Err(VaultCliError::Auth(format!(
                "No loopback address accepted the OIDC redirect listener ({}). Pass --port to \
                 use one the role also allows.",
                refusals.join("; ")
            )));
        }

        Ok(Self { sockets, port })
    }

    /// The redirect URI to register with the provider. Taken from the listener
    /// so the port asked for and the port bound cannot drift apart.
    pub fn redirect_uri(&self) -> String {
        format!("http://localhost:{}{CALLBACK_PATH}", self.port)
    }

    /// Serve until the callback arrives or the wait runs out.
    pub async fn accept(self) -> Result<Callback> {
        let port = self.port;
        let (found, mut arrived) = mpsc::channel(1);
        let servers: Vec<JoinHandle<()>> = self
            .sockets
            .into_iter()
            .map(|socket| {
                let found = found.clone();
                tokio::spawn(async move { serve(socket, found).await })
            })
            .collect();
        drop(found);

        let outcome = match tokio::time::timeout(WAIT, arrived.recv()).await {
            Ok(Some(outcome)) => outcome,
            // Every server ended without a callback, which only happens when
            // each of them stopped being able to accept.
            Ok(None) => Err(VaultCliError::Auth(
                "The OIDC redirect listener stopped before the provider redirected back."
                    .to_string(),
            )),
            // discard-ok: the elapsed error carries only that it elapsed, which
            // is what the message below says
            Err(_) => Err(VaultCliError::Auth(format!(
                "No OIDC redirect arrived within {} seconds. The browser may not have reached \
                 {CALLBACK_PATH} on this machine; over SSH, forward the port with \
                 `ssh -L {port}:localhost:{port}`.",
                WAIT.as_secs(),
            ))),
        };

        for server in servers {
            server.abort();
        }
        outcome
    }
}

/// What one connection turned out to be.
enum Served {
    /// Answered, and not the redirect. The wait goes on.
    Ignored,
    /// The redirect, carrying either the grant or what the provider refused
    /// with.
    Redirect(Result<Callback>),
}

/// Accept until one connection carries the redirect.
///
/// Each connection is served on its own task: a browser that opens a socket
/// speculatively and sends nothing would otherwise hold the accept loop until
/// the whole login timed out.
async fn serve(socket: TcpListener, found: mpsc::Sender<Result<Callback>>) {
    loop {
        let stream = match socket.accept().await {
            Ok((stream, _)) => stream,
            Err(e) => {
                tracing::error!("The OIDC redirect listener stopped accepting: {e}");
                return;
            }
        };

        let found = found.clone();
        tokio::spawn(async move {
            match tokio::time::timeout(REQUEST_WAIT, handle(stream)).await {
                Ok(Ok(Served::Redirect(outcome))) => {
                    // discard-ok: the receiver is gone only once the login
                    // finished, and a second redirect has nothing to add
                    let _ = found.send(outcome).await;
                }
                Ok(Ok(Served::Ignored)) => {
                    tracing::debug!("Ignoring a request that was not the OIDC redirect")
                }
                Ok(Err(e)) => {
                    tracing::warn!("Could not serve a request to the OIDC listener: {e}")
                }
                // discard-ok: the elapsed error carries only that it elapsed
                Err(_) => tracing::debug!(
                    "A connection to the OIDC listener sent no request within {} seconds",
                    REQUEST_WAIT.as_secs()
                ),
            }
        });
    }
}

/// One request: answer it, and say what it was.
async fn handle(mut stream: TcpStream) -> Result<Served> {
    let line = read_request_line(&mut stream).await?;
    let mut words = line.split(' ');
    let (Some(verb), Some(target)) = (words.next(), words.next()) else {
        return Err(VaultCliError::Auth(format!(
            "Unparseable request line: {line}"
        )));
    };

    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let served = match (path == CALLBACK_PATH, verb) {
        (false, _) => Served::Ignored,
        // The body is never read, so a mount configured to post its response
        // would otherwise leave the login waiting out its whole timeout on a
        // redirect that did arrive.
        (true, "POST") => Served::Redirect(Err(VaultCliError::Auth(
            "The identity provider posted its response instead of redirecting to it. Configure \
             the role for a query redirect; this listener reads no request body."
                .to_string(),
        ))),
        (true, _) => match parse_callback(query) {
            Some(outcome) => Served::Redirect(outcome),
            None => Served::Ignored,
        },
    };

    let (status, body) = match &served {
        Served::Ignored => ("404 Not Found", ""),
        Served::Redirect(Ok(_)) => ("200 OK", RECEIVED_PAGE),
        // discard-ok: nothing is dropped here — this picks the page the browser
        // gets, and the error itself travels on in `served` to the caller
        Served::Redirect(Err(_)) => ("400 Bad Request", REFUSED_PAGE),
    };
    stream
        .write_all(
            format!(
                "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await?;
    stream.shutdown().await?;

    Ok(served)
}

/// The first line only. Reading to end-of-stream would wait for a browser that
/// keeps the connection open.
async fn read_request_line(stream: &mut TcpStream) -> Result<String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];

    loop {
        match stream.read_exact(&mut byte).await {
            Ok(_) => {}
            // A browser that opens a connection and closes it again is
            // ordinary; anything else ended a request that had started.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }

        if byte[0] == b'\n' {
            break;
        }
        if line.len() >= MAX_REQUEST_LINE {
            return Err(VaultCliError::Auth(format!(
                "A request to the OIDC listener exceeded {MAX_REQUEST_LINE} bytes before its \
                 first line ended"
            )));
        }
        line.push(byte[0]);
    }

    Ok(String::from_utf8(line)?.trim_end().to_string())
}

/// What the provider put on the redirect. A query with no `state` belongs to no
/// login of ours; one carrying `error` is this login's, refused.
fn parse_callback(query: &str) -> Option<Result<Callback>> {
    let mut state = None;
    let mut code = None;
    let mut id_token = None;
    let mut error = None;
    let mut description = None;

    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "state" => state = Some(value.into_owned()),
            "code" => code = Some(value.into_owned()),
            "id_token" => id_token = Some(value.into_owned()),
            "error" => error = Some(value.into_owned()),
            "error_description" => description = Some(value.into_owned()),
            _ => {}
        }
    }

    let state = state?;
    if let Some(error) = error {
        return Some(Err(VaultCliError::Auth(match description {
            Some(description) => format!("The identity provider refused: {error} ({description})"),
            None => format!("The identity provider refused: {error}"),
        })));
    }

    // Exchanging an empty grant reports the provider's refusal as a malformed
    // request to Vault, naming neither.
    if code.is_none() && id_token.is_none() {
        return Some(Err(VaultCliError::Auth(
            "The identity provider redirected back with neither a code nor an identity token, \
             and said nothing about why."
                .to_string(),
        )));
    }

    Some(Ok(Callback {
        state,
        code: code.unwrap_or_default(),
        id_token,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The browser asks for more than the redirect, and the listener has to
    /// keep waiting through it rather than take the first request as an answer.
    #[tokio::test]
    async fn a_request_that_is_not_the_redirect_is_answered_and_ignored() {
        // Built rather than bound: `bind` refuses an ephemeral port, which is
        // the only kind two tests can ask for at once.
        let socket = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let port = socket.local_addr().expect("addr").port();
        let waiting = tokio::spawn(
            CallbackListener {
                sockets: vec![socket],
                port,
            }
            .accept(),
        );

        for target in ["/favicon.ico", "/oidc/callback?state=abc&code=xyz"] {
            let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                .await
                .expect("connect");
            stream
                .write_all(format!("GET {target} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
                .await
                .expect("request");
            let mut answer = String::new();
            stream.read_to_string(&mut answer).await.expect("answer");
            assert!(answer.starts_with("HTTP/1.1"), "{answer}");
        }

        let callback = waiting.await.expect("joined").expect("the redirect");
        assert_eq!(callback.state, "abc");
        assert_eq!(callback.code, "xyz");
    }

    /// A connection that sends nothing must not hold the accept loop: browsers
    /// open sockets speculatively, and the redirect would sit behind one until
    /// the whole login timed out.
    #[tokio::test]
    async fn a_silent_connection_does_not_hold_up_the_redirect() {
        let socket = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let port = socket.local_addr().expect("addr").port();
        let waiting = tokio::spawn(
            CallbackListener {
                sockets: vec![socket],
                port,
            }
            .accept(),
        );

        // Held open and never written to, exactly as a preconnect socket is.
        let _idle = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .expect("connect");

        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .expect("connect");
        stream
            .write_all(b"GET /oidc/callback?state=abc&code=xyz HTTP/1.1\r\n\r\n")
            .await
            .expect("request");

        let callback = waiting.await.expect("joined").expect("the redirect");
        assert_eq!(callback.code, "xyz");
    }

    /// Providers percent-encode what they hand back, and a code taken raw off
    /// the query is a code the token exchange refuses.
    #[test]
    fn the_query_is_decoded() {
        let callback = parse_callback("state=a%2Fb&code=c%2Bd")
            .expect("a redirect")
            .expect("a grant");
        assert_eq!(callback.state, "a/b");
        assert_eq!(callback.code, "c+d");
    }

    #[test]
    fn a_query_with_no_state_is_not_this_logins_redirect() {
        assert!(parse_callback("code=xyz").is_none());
    }

    /// A refusal carries `state` and no code. Read as a grant it exchanges an
    /// empty code, which reports the provider's reason as a malformed request
    /// to Vault and names neither.
    #[test]
    fn a_refusal_from_the_provider_is_reported_with_what_it_said() {
        let Some(Err(e)) =
            parse_callback("state=st&error=access_denied&error_description=Not+entitled")
        else {
            panic!("a refusal is this login's redirect, and is not a grant");
        };
        let err = e.to_string();
        assert!(err.contains("access_denied"), "{err}");
        assert!(err.contains("Not entitled"), "{err}");
    }

    #[test]
    fn a_redirect_with_no_grant_and_no_reason_is_still_refused() {
        // discard-ok: the assertion is which variant came back; the test above
        // covers what a refusal says
        assert!(matches!(parse_callback("state=st"), Some(Err(_))));
    }
}
