//! `session verify` — what a program needs of this Vault, checked with the
//! token that program will use.

use crate::cli::args::VerifyArgs;
use crate::config::Config;
use crate::utils::errors::{Result, VaultCliError};
use crate::utils::output::OutputFormat;
use vault_session::{Expectation, Finding, KvLayout, OidcLogin};

/// Whether anything was wrong, so the caller can pick an exit code.
pub async fn verify(args: VerifyArgs, config: &Config, output: &OutputFormat) -> Result<bool> {
    let session = crate::vault::operator_session().await?;
    let findings = vault_session::verify(&session, &expectation(args, config)?).await?;

    if output.json {
        output.print_json(&findings)?;
    } else {
        output.print_list(&findings.iter().map(Finding::to_string).collect::<Vec<_>>());
    }

    Ok(findings.is_empty())
}

fn expectation(args: VerifyArgs, config: &Config) -> Result<Expectation> {
    let mut expected = Expectation::default();

    for path in args.readable {
        expected = expected.read(path);
    }
    for path in args.writable {
        expected = expected.write(path);
    }
    for path in args.listable {
        expected = expected.list(path);
    }
    for named in &args.kv_mounts {
        let (mount, layout) = parse_kv_mount(named)?;
        expected = expected.kv_mount(mount, layout);
    }
    for name in args.policies {
        expected = expected.policy(name);
    }

    if let Some(mount) = config.oidc_mount(args.oidc_mount) {
        let mut login = OidcLogin::new(mount);
        login.role = config.oidc_role(args.oidc_role);
        if let Some(port) = config.oidc_port(args.oidc_port)? {
            login.redirect.port = port;
        }
        expected = expected.oidc(login);
    }

    Ok(expected)
}

/// `mount`, or `mount:1`/`mount:2` where the caller depends on the layout.
fn parse_kv_mount(named: &str) -> Result<(String, Option<KvLayout>)> {
    let Some((mount, layout)) = named.rsplit_once(':') else {
        return Ok((named.to_string(), None));
    };

    match layout {
        "1" => Ok((mount.to_string(), Some(KvLayout::Flat))),
        "2" => Ok((mount.to_string(), Some(KvLayout::Versioned))),
        other => Err(VaultCliError::InvalidInput(format!(
            "'{other}' is not a KV layout; write the mount alone, or `{mount}:1` or `{mount}:2`"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mount whose name contains a colon and no layout must not be read as a
    /// layout that does not exist.
    #[test]
    fn a_mount_named_without_a_layout_keeps_its_whole_name() {
        assert_eq!(
            parse_kv_mount("secret").expect("bare"),
            ("secret".to_string(), None)
        );
        assert_eq!(
            parse_kv_mount("secret:2").expect("versioned"),
            ("secret".to_string(), Some(KvLayout::Versioned))
        );
        parse_kv_mount("secret:3").expect_err("there are two layouts");
    }
}
