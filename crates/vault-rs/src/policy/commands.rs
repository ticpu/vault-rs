use crate::cli::args::PolicyCommands;
use crate::utils::errors::{Result, VaultCliError};
use crate::utils::output::OutputFormat;
use serde_json::json;
use std::io::Read;

pub async fn handle_policy_commands(command: PolicyCommands, output: &OutputFormat) -> Result<()> {
    match command {
        PolicyCommands::List => list(output).await,
        PolicyCommands::Read { name } => read(&name, output).await,
        PolicyCommands::Write { name, path } => write(&name, &path).await,
        PolicyCommands::Delete { name } => delete(&name).await,
        PolicyCommands::Forwarded(args) => {
            crate::vault::wrapper::exec_vault_command(
                &crate::vault::operator_session().await?,
                "policy",
                &args,
            )
            .await
        }
    }
}

async fn list(output: &OutputFormat) -> Result<()> {
    let client = crate::vault::operator_client().await?;
    let names = client.list_keys("sys/policies/acl").await?;

    match output.json {
        true => output.print_json(&names),
        false => {
            output.print_list(&names);
            Ok(())
        }
    }
}

/// The policy document itself, which is what a caller piping this into a file
/// or a diff is after; `--json` keeps the envelope Vault sent.
async fn read(name: &str, output: &OutputFormat) -> Result<()> {
    let client = crate::vault::operator_client().await?;
    let answer = client.get(&format!("sys/policies/acl/{name}")).await?;

    if output.json {
        return output.print_json(&answer);
    }

    let policy = answer["data"]["policy"].as_str().ok_or_else(|| {
        VaultCliError::InvalidInput(format!("'{name}' answered without a policy document"))
    })?;
    println!("{policy}");
    Ok(())
}

/// Replaces whatever is there. Vault has no merge for a policy, so a write
/// that meant to add a rule and left the others out silently removes them —
/// the document handed in is the whole policy.
async fn write(name: &str, path: &str) -> Result<()> {
    let policy = match path {
        "-" => {
            let mut document = String::new();
            std::io::stdin().read_to_string(&mut document)?;
            document
        }
        path => std::fs::read_to_string(path)?,
    };

    let client = crate::vault::operator_client().await?;
    client
        .post(
            &format!("sys/policies/acl/{name}"),
            json!({ "policy": policy }),
        )
        .await?;

    eprintln!("Wrote the '{name}' policy");
    Ok(())
}

async fn delete(name: &str) -> Result<()> {
    let client = crate::vault::operator_client().await?;
    client.delete(&format!("sys/policies/acl/{name}")).await?;

    eprintln!("Deleted the '{name}' policy");
    Ok(())
}
