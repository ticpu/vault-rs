use crate::cli::args::{Cli, CompletionCommands, CompletionHelperCommands};
use crate::utils::errors::Result;
use crate::utils::output::OutputFormat;
use crate::vault::client::VaultClient;
use clap::CommandFactory;
use clap_complete::{generate, Shell};
use std::io;

pub fn handle_completion_command(command: &CompletionCommands, _cli: &Cli) -> Result<()> {
    let shell = command.shell();
    let mut cmd = Cli::command();
    let app_name = "vault-rs";

    // For bash, add our custom completion enhancement first
    if matches!(shell, Shell::Bash) {
        println!("# Enhanced completion for vault-rs PKI mounts and roles");
        print!(
            r#"
_vault_rs_complete_pki_mounts() {{
    local mounts
    mounts=$(vault-rs completion-helper pki-mounts 2>/dev/null)
    COMPREPLY=($(compgen -W "$mounts" -- "${{cur}}"))
}}

_vault_rs_complete_roles() {{
    local roles pki_mount
    # Find the PKI mount from previous arguments
    local i=0
    for word in "${{COMP_WORDS[@]}}"; do
        if [[ $i -gt 0 && "${{COMP_WORDS[$((i-1))]}}" != "-"* ]]; then
            case "${{COMP_WORDS[$((i-1))]}}" in
                "list-roles"|"create"|"sign")
                    pki_mount="$word"
                    break
                    ;;
            esac
        fi
        ((i++))
    done
    
    if [[ -n "$pki_mount" ]]; then
        roles=$(vault-rs completion-helper roles "$pki_mount" 2>/dev/null)
        COMPREPLY=($(compgen -W "$roles" -- "${{cur}}"))
    fi
}}

# Override the generated completion for specific arguments
_vault_rs_override() {{
    local cur prev words cword
    _init_completion || return

    case "${{words[*]}}" in
        *"cert list"*|*"cert list-roles"*|*"cert create"*|*"cert sign"*)
            # Check if we're completing a PKI mount argument
            case "$prev" in
                "list-roles"|"create"|"sign")
                    _vault_rs_complete_pki_mounts
                    return 0
                    ;;
                "--pki-mount"|"-m")
                    _vault_rs_complete_pki_mounts
                    return 0
                    ;;
                "--role")
                    _vault_rs_complete_roles
                    return 0
                    ;;
            esac
            ;;
    esac
    
    # Fall back to the original completion
    _vault-rs "$@"
}}

"#
        );

        // Generate the base completion
        generate(shell, &mut cmd, app_name, &mut io::stdout());

        println!();
        println!("# Override the completion function");
        println!("complete -F _vault_rs_override vault-rs");
    } else {
        // For non-bash shells, just generate the standard completion
        generate(shell, &mut cmd, app_name, &mut io::stdout());
    }

    Ok(())
}

pub async fn handle_completion_helper_command(
    command: &CompletionHelperCommands,
    output: &OutputFormat,
) -> Result<()> {
    let client = VaultClient::new().await;

    match command {
        CompletionHelperCommands::PkiMounts => {
            if let Ok(pki_mounts) = client.list_pki_mounts().await {
                output.print_list(&pki_mounts);
            }
        }
        CompletionHelperCommands::Roles { pki_mount } => {
            if let Ok(roles) = client.list_roles(pki_mount).await {
                output.print_list(&roles);
            }
        }
    }

    Ok(())
}
