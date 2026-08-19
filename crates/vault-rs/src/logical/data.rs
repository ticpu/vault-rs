//! `key=value` request data, in the spelling Vault's own CLI accepts.
//!
//! The flags on these commands are this tool's, but the data is not: an
//! operator pasting a documented invocation is pasting its data arguments, and
//! a value loaded from a file or from stdin is the reason those spellings
//! exist at all.

use crate::utils::errors::{Result, VaultCliError};
use serde_json::{Map, Value};
use std::io::Read;

/// Parse `key=value` arguments into a request body.
///
/// A value of `-` is read from stdin and one beginning with `@` from a file;
/// `\@` is a literal `@`. A key repeated becomes a list, which is how a request
/// takes more than one policy or alternative name.
///
/// An argument with no `=` supplies the whole body as JSON, from the same two
/// sources, and may be mixed with `key=value` arguments. The two collide
/// differently and deliberately: a whole body replaces a key already set, while
/// a `key=value` for a key already present extends it into a list.
pub fn parse(args: &[String], stdin: &mut impl Read) -> Result<Map<String, Value>> {
    let mut body = Map::new();

    for arg in args {
        match arg.split_once('=') {
            None => merge_whole_body(&mut body, arg, stdin)?,
            Some((key, value)) => {
                let value = Value::String(load(value, stdin)?);
                match body.remove(key) {
                    // A key given twice is a list, and a third occurrence
                    // extends it rather than nesting.
                    Some(Value::Array(mut existing)) => {
                        existing.push(value);
                        body.insert(key.to_string(), Value::Array(existing));
                    }
                    Some(first) => {
                        body.insert(key.to_string(), Value::Array(vec![first, value]));
                    }
                    None => {
                        body.insert(key.to_string(), value);
                    }
                }
            }
        }
    }

    Ok(body)
}

/// A whole request body, which has to be a JSON object: merging anything else
/// into the keys around it has no meaning, and silently taking the last one
/// would discard what the other arguments set.
fn merge_whole_body(body: &mut Map<String, Value>, arg: &str, stdin: &mut impl Read) -> Result<()> {
    let source = load(arg, stdin)?;
    let parsed: Value = serde_json::from_str(&source).map_err(|e| {
        VaultCliError::InvalidInput(format!(
            "'{arg}' has no '=', so it is read as a whole request body, and it is not JSON: {e}"
        ))
    })?;

    match parsed {
        Value::Object(fields) => {
            body.extend(fields);
            Ok(())
        }
        other => Err(VaultCliError::InvalidInput(format!(
            "'{arg}' is read as a whole request body, which has to be a JSON object, not {}",
            kind(&other)
        ))),
    }
}

fn kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "a list",
        Value::Object(_) => "an object",
    }
}

/// The literal value, or what the file or stdin it names holds.
fn load(value: &str, stdin: &mut impl Read) -> Result<String> {
    if value == "-" {
        let mut read = String::new();
        stdin.read_to_string(&mut read).map_err(|e| {
            VaultCliError::InvalidInput(format!("cannot read the value from stdin: {e}"))
        })?;
        return Ok(read);
    }

    if let Some(escaped) = value.strip_prefix("\\@") {
        return Ok(format!("@{escaped}"));
    }

    match value.strip_prefix('@') {
        Some(file) => std::fs::read_to_string(file)
            .map_err(|e| VaultCliError::InvalidInput(format!("cannot read '{file}': {e}"))),
        None => Ok(value.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse_args(args: &[&str], stdin: &str) -> Result<Map<String, Value>> {
        let owned: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        parse(&owned, &mut stdin.as_bytes())
    }

    #[test]
    fn a_pair_is_a_string_and_a_repeated_key_is_a_list() {
        let body = parse_args(&["a=1", "p=admin", "p=secops"], "").expect("parsed");
        assert_eq!(body["a"], json!("1"));
        assert_eq!(body["p"], json!(["admin", "secops"]));
    }

    #[test]
    fn a_key_given_three_times_extends_the_list_rather_than_nesting() {
        let body = parse_args(&["p=a", "p=b", "p=c"], "").expect("parsed");
        assert_eq!(body["p"], json!(["a", "b", "c"]));
    }

    #[test]
    fn a_value_of_dash_comes_from_stdin() {
        let body = parse_args(&["token=-"], "s.from-stdin").expect("parsed");
        assert_eq!(body["token"], json!("s.from-stdin"));
    }

    /// The whole-body form is not required to be the only argument, and the two
    /// forms collide differently: the body replaced the pair before it, and the
    /// pair after it extended the result into a list. Pinned against what the
    /// official binary emits for the same arguments, since nothing about the
    /// asymmetry is guessable.
    #[test]
    fn a_whole_body_replaces_a_pair_but_a_later_pair_extends_it() {
        let body = parse_args(
            &["kept=1", "-", "kept=2"],
            r#"{"from_body": "yes", "kept": "0"}"#,
        )
        .expect("parsed");
        assert_eq!(body["from_body"], json!("yes"));
        assert_eq!(body["kept"], json!(["0", "2"]));
    }

    #[test]
    fn a_whole_body_that_is_not_an_object_is_refused() {
        let err = parse_args(&["-"], "[1, 2]")
            .expect_err("a list is not a request body")
            .to_string();
        assert!(err.contains("JSON object"), "{err}");
    }

    #[test]
    fn a_whole_body_that_is_not_json_names_the_argument() {
        let err = parse_args(&["-"], "not json")
            .expect_err("refused")
            .to_string();
        assert!(err.contains("whole request body"), "{err}");
    }

    /// Without the escape there would be no way to send a value that starts
    /// with the character naming a file.
    #[test]
    fn a_value_starting_with_an_at_sign_escapes() {
        let body = parse_args(&[r"user=\@example.test"], "").expect("parsed");
        assert_eq!(body["user"], json!("@example.test"));
    }

    #[test]
    fn a_missing_file_names_the_file() {
        let err = parse_args(&["policy=@no/such/file.json"], "")
            .expect_err("refused")
            .to_string();
        assert!(err.contains("no/such/file.json"), "{err}");
    }

    /// A value carrying its own separators keeps them: only the first splits.
    #[test]
    fn only_the_first_separator_splits() {
        let body = parse_args(&["url=https://vault.example.test:8200/v1"], "").expect("parsed");
        assert_eq!(body["url"], json!("https://vault.example.test:8200/v1"));
    }
}
