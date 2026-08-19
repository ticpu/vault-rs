//! Checking that a Vault is set up the way a program needs, using only reads
//! the program's own token can perform.
//!
//! Nothing here provisions: a finding says what is wrong and leaves fixing it
//! to whoever holds the rights to fix it.

use crate::client::{KvLayout, VaultClient};
use crate::error::Result;
use crate::session::{OidcLogin, Session};
use serde::Serialize;
use std::fmt;

/// What a caller needs to be true before its program can work.
///
/// A field left empty is a thing not checked.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct Expectation {
    /// Paths the token has to be able to read, spelled exactly as the program
    /// will address them. A KV mount's two layouts reach a secret through
    /// different prefixes, so a policy written for the other one grants
    /// nothing at the path that is actually read.
    pub readable: Vec<String>,
    pub writable: Vec<String>,
    pub listable: Vec<String>,
    /// Mounts that have to be there, each with the layout it has to have where
    /// the caller depends on one.
    pub kv_mounts: Vec<(String, Option<KvLayout>)>,
    /// Policies that have to be attached to the token.
    pub policies: Vec<String>,
    /// A login whose role has to allow the loopback callback a real login
    /// would bind.
    pub oidc: Option<OidcLogin>,
}

impl Expectation {
    pub fn read(mut self, path: impl Into<String>) -> Self {
        self.readable.push(path.into());
        self
    }

    pub fn write(mut self, path: impl Into<String>) -> Self {
        self.writable.push(path.into());
        self
    }

    pub fn list(mut self, path: impl Into<String>) -> Self {
        self.listable.push(path.into());
        self
    }

    /// A layout left absent accepts whichever the mount has.
    pub fn kv_mount(mut self, mount: impl Into<String>, layout: Option<KvLayout>) -> Self {
        self.kv_mounts.push((mount.into(), layout));
        self
    }

    pub fn policy(mut self, name: impl Into<String>) -> Self {
        self.policies.push(name.into());
        self
    }

    pub fn oidc(mut self, login: OidcLogin) -> Self {
        self.oidc = Some(login);
        self
    }
}

/// One thing `verify` found wrong. An empty report is the only pass.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "finding", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Finding {
    /// The token may not do this at the path.
    #[non_exhaustive]
    Denied {
        path: String,
        wanted: &'static str,
        granted: Vec<String>,
    },
    /// Nothing the token can see is mounted there.
    #[non_exhaustive]
    MountAbsent { mount: String },
    /// The mount is there under the other layout.
    #[non_exhaustive]
    WrongLayout {
        mount: String,
        wanted: KvLayout,
        found: KvLayout,
    },
    /// Vault drops a policy name it does not know rather than refusing the
    /// login, so a token can come back holding fewer than it was granted.
    #[non_exhaustive]
    PolicyNotAttached { name: String, attached: Vec<String> },
    /// The role would not accept the redirect a login binds.
    #[non_exhaustive]
    RedirectRefused { mount: String, reason: String },
    /// The check itself could not be run, so nothing is claimed either way.
    #[non_exhaustive]
    Unchecked {
        checking: &'static str,
        reason: String,
    },
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied {
                path,
                wanted,
                granted,
            } => write!(
                f,
                "the token cannot {wanted} '{path}' (Vault grants it {})",
                match granted.is_empty() {
                    true => "nothing there".to_string(),
                    false => granted.join(", "),
                }
            ),
            Self::MountAbsent { mount } => {
                write!(f, "no mount the token can see is at '{mount}'")
            }
            Self::WrongLayout {
                mount,
                wanted,
                found,
            } => write!(
                f,
                "'{mount}' is a {found:?} KV mount; this needs a {wanted:?} one, which addresses \
                 a secret through different prefixes"
            ),
            Self::PolicyNotAttached { name, attached } => write!(
                f,
                "the token does not carry the '{name}' policy (it carries {})",
                match attached.is_empty() {
                    true => "none".to_string(),
                    false => attached.join(", "),
                }
            ),
            Self::RedirectRefused { mount, reason } => {
                write!(f, "the '{mount}' auth mount refused a login: {reason}")
            }
            Self::Unchecked { checking, reason } => {
                write!(f, "could not check {checking}: {reason}")
            }
        }
    }
}

/// Run every check the expectation names and report what is wrong.
///
/// A check that could not run is a `Unchecked` finding rather than an early
/// return: an operator fixing a setup wants the whole list, not the first
/// thing that stopped the run.
pub async fn verify(session: &Session, expected: &Expectation) -> Result<Vec<Finding>> {
    let client = VaultClient::for_session(session).await?;
    let mut findings = Vec::new();

    check_capabilities(&client, expected, &mut findings).await;
    check_mounts(&client, expected, &mut findings).await;
    check_policies(&client, expected, &mut findings).await;

    if let Some(login) = &expected.oidc {
        if let Err(e) = session.preflight_oidc(login).await {
            findings.push(Finding::RedirectRefused {
                mount: login.mount.clone(),
                reason: crate::error::render_chain(&e),
            });
        }
    }

    Ok(findings)
}

async fn check_capabilities(
    client: &VaultClient,
    expected: &Expectation,
    findings: &mut Vec<Finding>,
) {
    // Vault answers about every path in one request, so the whole expectation
    // costs one round trip however many paths it names.
    let wanted: Vec<(&str, &'static str)> = [
        (&expected.readable, "read"),
        (&expected.writable, "write"),
        (&expected.listable, "list"),
    ]
    .into_iter()
    .flat_map(|(paths, verb)| paths.iter().map(move |path| (path.as_str(), verb)))
    .collect();

    if wanted.is_empty() {
        return;
    }

    let paths: Vec<&str> = wanted.iter().map(|(path, _)| *path).collect();
    let reported = match client.capabilities(&paths).await {
        Ok(reported) => reported,
        Err(e) => {
            findings.push(Finding::Unchecked {
                checking: "what the token may do",
                reason: crate::error::render_chain(&e),
            });
            return;
        }
    };

    for ((path, verb), capabilities) in wanted.iter().zip(reported) {
        let allowed = match *verb {
            "read" => capabilities.can_read(),
            "write" => capabilities.can_write(),
            _ => capabilities.can_list(),
        };
        if !allowed {
            findings.push(Finding::Denied {
                path: (*path).to_string(),
                wanted: verb,
                granted: capabilities.granted,
            });
        }
    }
}

async fn check_mounts(client: &VaultClient, expected: &Expectation, findings: &mut Vec<Finding>) {
    if expected.kv_mounts.is_empty() {
        return;
    }

    let visible = match client.visible_mounts().await {
        Ok(visible) => visible.kv_mounts(),
        Err(e) => {
            findings.push(Finding::Unchecked {
                checking: "which mounts the token can see",
                reason: crate::error::render_chain(&e),
            });
            return;
        }
    };

    for (mount, wanted) in &expected.kv_mounts {
        let mount = mount.trim_matches('/');
        let Some((_, found)) = visible.iter().find(|(seen, _)| seen == mount) else {
            findings.push(Finding::MountAbsent {
                mount: mount.to_string(),
            });
            continue;
        };

        if wanted.is_some_and(|wanted| wanted != *found) {
            findings.push(Finding::WrongLayout {
                mount: mount.to_string(),
                wanted: wanted.expect("checked above"),
                found: *found,
            });
        }
    }
}

async fn check_policies(client: &VaultClient, expected: &Expectation, findings: &mut Vec<Finding>) {
    if expected.policies.is_empty() {
        return;
    }

    let attached = match client.token_policies().await {
        Ok(attached) => attached,
        Err(e) => {
            findings.push(Finding::Unchecked {
                checking: "which policies the token carries",
                reason: crate::error::render_chain(&e),
            });
            return;
        }
    };

    for name in &expected.policies {
        if !attached.contains(name) {
            findings.push(Finding::PolicyNotAttached {
                name: name.clone(),
                attached: attached.clone(),
            });
        }
    }
}
