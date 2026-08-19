//! The file of defaults, and how a setting is chosen between it and the flags.
//!
//! A flag wins over a `VAULT_RS_`-prefixed variable, which wins over the file,
//! which wins over the built-in. Nothing here decides what a setting means:
//! each resolver fills a `None` the command line left, and the built-in is
//! whatever the command already did without a file.

use crate::utils::cli_paths::CliPaths;
use crate::utils::errors::{Result, VaultCliError};
use serde::Deserialize;
use std::env;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// Where the file lives when the operator names no path.
pub const FILE_NAME: &str = "config.yaml";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The PKI mount every certificate verb looks at. Absent means all of them,
    /// which is what a search with no mount named has always done.
    pub pki_mount: Option<String>,
    #[serde(default)]
    pub login: Login,
    pub output: Option<OutputMode>,
    #[serde(default)]
    pub columns: Columns,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Login {
    pub method: Option<String>,
    pub oidc_mount: Option<String>,
    pub oidc_role: Option<String>,
    pub oidc_port: Option<u16>,
}

/// A comma-separated column list, in the syntax `--columns` already takes. A
/// configured list replaces the built-in defaults outright, so a `+` entry on
/// the command line adds to the configured one.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Columns {
    pub cert_list: Option<String>,
    pub storage_list: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutputMode {
    Formatted,
    Raw,
    Json,
}

impl Config {
    /// The file the operator named, or the one at the default path.
    ///
    /// A named path that does not exist is an error: asking for a file and
    /// silently running on built-in defaults is how a config that never applied
    /// goes unnoticed. The default path is allowed to hold nothing, since not
    /// having a config file is the ordinary case. Unreadable or malformed is an
    /// error either way, including a key the file has no field for.
    pub fn load(named: Option<&Path>) -> Result<Self> {
        let (path, named) = match named {
            Some(path) => (path.to_path_buf(), true),
            None => (Self::default_path()?, false),
        };

        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == ErrorKind::NotFound && !named => return Ok(Self::default()),
            Err(e) => {
                return Err(VaultCliError::Config(format!(
                    "cannot read the config file '{}': {e}",
                    path.display()
                )))
            }
        };

        serde_yaml_ng::from_str(&text).map_err(|e| {
            VaultCliError::Config(format!("'{}' is not a valid config: {e}", path.display()))
        })
    }

    pub fn default_path() -> Result<PathBuf> {
        Ok(CliPaths::config_dir()?.join(FILE_NAME))
    }

    /// The PKI mount a certificate verb should look at, or `None` for every
    /// mount the token can see.
    pub fn pki_mount(&self, flag: Option<String>) -> Option<String> {
        flag.or_else(|| named("VAULT_RS_PKI_MOUNT"))
            .or_else(|| self.pki_mount.clone())
    }

    pub fn login_method(&self, flag: Option<String>) -> Option<String> {
        flag.or_else(|| named("VAULT_RS_LOGIN_METHOD"))
            .or_else(|| self.login.method.clone())
    }

    pub fn oidc_mount(&self, flag: Option<String>) -> Option<String> {
        flag.or_else(|| named("VAULT_RS_OIDC_MOUNT"))
            .or_else(|| self.login.oidc_mount.clone())
    }

    pub fn oidc_role(&self, flag: Option<String>) -> Option<String> {
        flag.or_else(|| named("VAULT_RS_OIDC_ROLE"))
            .or_else(|| self.login.oidc_role.clone())
    }

    pub fn oidc_port(&self, flag: Option<u16>) -> Result<Option<u16>> {
        if let Some(port) = flag {
            return Ok(Some(port));
        }
        match named("VAULT_RS_OIDC_PORT") {
            Some(text) => text.parse().map(Some).map_err(|e| {
                VaultCliError::Config(format!("VAULT_RS_OIDC_PORT is not a port number: {e}"))
            }),
            None => Ok(self.login.oidc_port),
        }
    }

    pub fn cert_list_columns(&self, flag: Option<String>) -> Option<String> {
        flag.or_else(|| named("VAULT_RS_COLUMNS_CERT_LIST"))
            .or_else(|| self.columns.cert_list.clone())
    }

    pub fn storage_list_columns(&self, flag: Option<String>) -> Option<String> {
        flag.or_else(|| named("VAULT_RS_COLUMNS_STORAGE_LIST"))
            .or_else(|| self.columns.storage_list.clone())
    }

    /// The output mode, given the two flags that name one. Neither flag set
    /// leaves the variable and then the file to answer.
    pub fn output_mode(&self, raw: bool, json: bool) -> Result<OutputMode> {
        if raw {
            return Ok(OutputMode::Raw);
        }
        if json {
            return Ok(OutputMode::Json);
        }
        match named("VAULT_RS_OUTPUT") {
            Some(text) => match text.as_str() {
                "formatted" => Ok(OutputMode::Formatted),
                "raw" => Ok(OutputMode::Raw),
                "json" => Ok(OutputMode::Json),
                other => Err(VaultCliError::Config(format!(
                    "VAULT_RS_OUTPUT is '{other}', not formatted, raw or json"
                ))),
            },
            None => Ok(self.output.unwrap_or(OutputMode::Formatted)),
        }
    }
}

/// A variable that is set to something. An empty one is treated as unset, so
/// clearing it in a shell profile returns the setting to the file.
fn named(variable: &str) -> Option<String> {
    match env::var(variable) {
        Ok(value) if !value.is_empty() => Some(value),
        // discard-ok: unset and non-UTF-8 both mean this variable answers nothing
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Result<Config> {
        serde_yaml_ng::from_str(yaml).map_err(|e| VaultCliError::Config(e.to_string()))
    }

    #[test]
    fn an_empty_file_is_every_setting_unset() {
        let config = parse("{}").expect("empty mapping");
        assert!(config.pki_mount.is_none());
        assert!(config.login.method.is_none());
        assert!(config.columns.cert_list.is_none());
        assert!(config.output.is_none());
    }

    /// A typo'd key would otherwise leave the operator with a file that parses
    /// and changes nothing.
    #[test]
    fn a_key_with_no_field_is_refused() {
        let error = parse("pki_mount: pki\nkolumns: cn\n").expect_err("unknown key");
        assert!(
            error.to_string().contains("kolumns"),
            "the message names the key: {error}"
        );
    }

    #[test]
    fn a_flag_wins_over_the_file() {
        let config = parse("pki_mount: from-file").expect("config");
        assert_eq!(
            config.pki_mount(Some("from-flag".to_string())),
            Some("from-flag".to_string())
        );
    }

    #[test]
    fn the_file_answers_where_no_flag_did() {
        let config = parse("pki_mount: from-file").expect("config");
        assert_eq!(config.pki_mount(None), Some("from-file".to_string()));
    }

    /// The built-in for a mount is every mount, not a named one.
    #[test]
    fn no_flag_and_no_file_leaves_the_mount_unnamed() {
        assert_eq!(Config::default().pki_mount(None), None);
    }

    #[test]
    fn a_named_path_that_is_not_there_is_an_error() {
        let missing = CliPaths::config_dir()
            .expect("config dir")
            .join("no-such-config.yaml");
        let error = Config::load(Some(&missing)).expect_err("a named path has to exist");
        assert!(
            error.to_string().contains("no-such-config"),
            "the message names the path: {error}"
        );
    }

    #[test]
    fn a_flag_wins_over_the_file_for_output() {
        let config = parse("output: json").expect("config");
        assert_eq!(
            config.output_mode(true, false).expect("raw"),
            OutputMode::Raw
        );
        assert_eq!(
            config.output_mode(false, false).expect("file"),
            OutputMode::Json
        );
    }
}
