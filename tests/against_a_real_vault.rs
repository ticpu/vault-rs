//! What only a real server can answer.
//!
//! These cover the contracts a mocked response cannot: exit codes, which
//! stream a line went to, and whether a path this tool builds is one Vault
//! actually accepts. A stub agrees with whatever the code believes.

mod common;

use common::{skipped, DevVault};

/// Every test names its own scratch directory, since they run in parallel and
/// each gets its own server and its own store.
macro_rules! vault {
    ($name:literal) => {{
        if skipped() {
            return;
        }
        DevVault::start($name)
    }};
}

#[test]
fn a_write_is_readable_and_a_field_comes_back_bare() {
    let vault = vault!("write-read");

    vault
        .run(&["write", "secret/data/app", "data=@-"])
        .failed_with(2);

    vault
        .run(&["kv", "put", "secret/app", "user=admin", "token=s.abc"])
        .succeeded();

    vault
        .run(&["kv", "get", "secret/app"])
        .succeeded()
        .stdout_has("admin");

    // A bare value has nothing to strip back off, which is the point of the
    // flag: it is what a shell substitutes.
    let field = vault.run(&["kv", "get", "--field", "token", "secret/app"]);
    field.succeeded();
    assert_eq!(field.stdout, "s.abc\n", "{}", field.report());
}

/// Data goes to stdout and everything addressed to a person to stderr, or a
/// pipeline reading the first gets the second.
#[test]
fn only_records_reach_stdout() {
    let vault = vault!("streams");
    vault.run(&["kv", "put", "secret/app", "k=v"]).succeeded();

    vault
        .run(&["kv", "delete", "secret/app"])
        .succeeded()
        .stdout_lacks("Deleted")
        .stderr_has("Deleted");
}

#[test]
fn the_value_spellings_reach_the_server_intact() {
    let vault = vault!("value-spellings");
    let file = vault.scratch_path("policy.json");
    std::fs::write(&file, r#"{"rule": "from a file"}"#).expect("fixture");

    vault
        .run_with_stdin(
            &[
                "kv",
                "put",
                "secret/app",
                "plain=literal",
                &format!("fromfile=@{}", file.display()),
                "fromstdin=-",
                "list=one",
                "list=two",
            ],
            "piped-value",
        )
        .succeeded();

    let read = vault.run(&["--json", "kv", "get", "secret/app"]);
    read.succeeded()
        .stdout_has("literal")
        .stdout_has("from a file")
        .stdout_has("piped-value")
        .stdout_has("one")
        .stdout_has("two");
}

/// The two layouts address a secret differently, and the difference is the
/// thing most easily got wrong without a server to reject it.
#[test]
fn both_layouts_round_trip() {
    let vault = vault!("layouts");
    vault.enable("kv", "flat");

    vault
        .run(&["kv", "put", "flat/thing", "k=flat-value"])
        .succeeded();
    vault
        .run(&["kv", "get", "flat/thing"])
        .succeeded()
        .stdout_has("flat-value");

    // A verb the flat layout has no prefix for is refused by name rather than
    // sent to a path that does not exist.
    vault
        .run(&["kv", "rollback", "--version", "1", "flat/thing"])
        .failed_with(2)
        .stderr_has("no version history");

    vault
        .run(&["kv", "put", "secret/thing", "k=versioned-value"])
        .succeeded();
    vault
        .run(&["kv", "get", "secret/thing"])
        .succeeded()
        .stdout_has("versioned-value");
}

/// The mount flag and the joined path name the same secret.
#[test]
fn the_two_spellings_agree() {
    let vault = vault!("spellings");
    vault
        .run(&["kv", "put", "--mount", "secret", "app/config", "k=v"])
        .succeeded();

    vault
        .run(&["kv", "get", "secret/app/config"])
        .succeeded()
        .stdout_has("v");
}

#[test]
fn a_version_can_be_withdrawn_and_brought_back() {
    let vault = vault!("versions");
    vault
        .run(&["kv", "put", "secret/app", "k=first"])
        .succeeded();
    vault
        .run(&["kv", "put", "secret/app", "k=second"])
        .succeeded();

    vault
        .run(&["kv", "get", "--version", "1", "secret/app"])
        .succeeded()
        .stdout_has("first");

    vault
        .run(&["kv", "rollback", "--version", "1", "secret/app"])
        .succeeded();
    vault
        .run(&["kv", "get", "secret/app"])
        .succeeded()
        .stdout_has("first");

    vault
        .run(&["kv", "delete", "--version", "3", "secret/app"])
        .succeeded();

    // Its value is withdrawn, so restoring it would write an empty secret over
    // a good one.
    vault
        .run(&["kv", "rollback", "--version", "3", "secret/app"])
        .failed_with(2)
        .stderr_has("undelete");

    vault
        .run(&["kv", "undelete", "--version", "3", "secret/app"])
        .succeeded();

    vault
        .run(&["kv", "destroy", "--version", "1", "secret/app"])
        .succeeded();
    vault
        .run(&["kv", "rollback", "--version", "1", "secret/app"])
        .failed_with(2)
        .stderr_has("destroyed");
}

/// The check that gates the master-key notice is a string comparison, so this
/// is about whether the path it then builds is one the server serves.
#[test]
fn the_master_key_path_is_announced_and_others_are_not() {
    let vault = vault!("master-key-notice");

    vault
        .run(&["kv", "put", "secret/app/config", "k=v"])
        .succeeded()
        .stderr_lacks("master key");

    vault
        .run(&["kv", "put", "secret/vault-rs/encryption-key", "key=00"])
        .succeeded()
        .stderr_has("master key")
        .stderr_has("session init-encryption");
}

#[test]
fn the_master_key_has_a_history_and_a_way_back() {
    let vault = vault!("key-recovery");

    vault.run(&["session", "init-encryption"]).succeeded();
    vault
        .run(&["session", "key", "status"])
        .succeeded()
        .stdout_has("secret")
        .stdout_has("cluster_reached");

    vault.run(&["session", "key", "history"]).succeeded();

    // Nothing was issued into this store, so there is nothing to verify the
    // restore against, and saying so is a different answer from success.
    vault
        .run(&["session", "key", "restore", "--version", "1"])
        .succeeded()
        .stderr_has("Nothing in the local store");
}

/// A store with no key must not be reported as one with an empty key, and a
/// second init must not replace what the first wrote.
#[test]
fn initialising_the_key_twice_is_refused() {
    let vault = vault!("init-twice");
    vault.run(&["session", "init-encryption"]).succeeded();

    vault
        .run(&["session", "init-encryption"])
        .failed_with(2)
        .stderr_has("--destroy-all-my-keys");
}

#[test]
fn a_reachable_unsealed_vault_reports_itself() {
    let vault = vault!("status");

    vault
        .run(&["status"])
        .succeeded()
        .stdout_has("sealed")
        .stdout_has("cluster_id");

    vault
        .run(&["secrets", "list"])
        .succeeded()
        .stdout_has("secret");
}

/// The subcommands this tool does not model reach the binary, which is the
/// half of the split that has no unit test.
#[test]
fn unmodelled_subcommands_reach_the_official_binary() {
    let vault = vault!("forwarding");
    vault.run(&["kv", "put", "secret/app", "k=v"]).succeeded();

    vault
        .run(&["kv", "patch", "secret/app", "added=yes"])
        .succeeded();
    vault
        .run(&["kv", "get", "secret/app"])
        .succeeded()
        .stdout_has("added");

    vault
        .run(&["auth", "list"])
        .succeeded()
        .stdout_has("token/");
}

#[test]
fn the_token_verbs_act_on_this_session() {
    let vault = vault!("token");

    vault
        .run(&["token", "lookup"])
        .succeeded()
        .stdout_has("display_name");

    vault.run(&["session", "login", "--help"]).succeeded();
}

/// The confinement is a claim about the kernel, so it is checked rather than
/// trusted: this writes where a stray test would and expects to be refused.
///
/// It runs after a server has started, because that is what applies the
/// restriction to this thread.
#[test]
fn these_tests_cannot_write_outside_their_scratch_directory() {
    let vault = vault!("confinement");

    let inside = vault.scratch_path("allowed");
    std::fs::write(&inside, "scratch").expect("writing inside the scratch directory");

    let home = std::env::var("HOME").expect("a home to be kept out of");
    for outside in [
        // Just outside the boundary, which is where an off-by-one in the rule
        // would show.
        std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/target"))
            .join("vault-rs-should-never-appear"),
        // The one that matters.
        std::path::Path::new(&home).join(".vault-rs-should-never-appear"),
    ] {
        match std::fs::write(&outside, "this must not land") {
            Ok(()) => {
                // discard-ok: removing what should never have been written; the
                // panic below is the report either way
                let _ = std::fs::remove_file(&outside);
                panic!(
                    "wrote to {} — these tests are not confined, so a stray path would reach a \
                     real home",
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
}

/// What the role decides is read off a live role, and the fields that decide
/// it are marked as deciding rather than being three lines among forty.
#[test]
fn a_role_reports_what_it_decides_about_an_issuance() {
    let vault = vault!("role-info");
    vault.enable("pki", "pki");
    vault
        .run(&[
            "write",
            "pki/root/generate/internal",
            "common_name=Example Issuing CA",
            "ttl=87600h",
        ])
        .succeeded();
    vault
        .run(&[
            "write",
            "pki/roles/client",
            "allow_any_name=true",
            "client_flag=true",
            "server_flag=false",
            "organization=Example Org",
            "use_csr_common_name=false",
            "max_ttl=72h",
        ])
        .succeeded();

    let shown = vault.run(&["cert", "role-info", "pki", "client"]);
    shown
        .succeeded()
        .stdout_has("Example Org")
        .stdout_has("ClientAuth")
        // The CN has no source yet, and saying so beats rendering an empty one.
        .stdout_has("supplied at issuance")
        .stdout_has("Example Issuing CA");

    // The flag spelling names the same role.
    vault
        .run(&["cert", "role-info", "-m", "pki", "client"])
        .succeeded()
        .stdout_has("ClientAuth");

    // The whole record, not the parsed subset: a field the struct does not
    // model still has to come back.
    vault
        .run(&["--json", "cert", "role-info", "pki", "client"])
        .succeeded()
        .stdout_has("allow_any_name");
}

/// A path that holds nothing is a refusal carrying its status, not an empty
/// record.
#[test]
fn an_absent_path_is_refused_rather_than_answered_empty() {
    let vault = vault!("absent");

    vault
        .run(&["kv", "get", "secret/never-written"])
        .failed_with(2)
        .stdout_lacks("secret/never-written");
}
