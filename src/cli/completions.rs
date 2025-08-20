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

_vault_rs_complete_columns() {{
    local columns
    columns=$(vault-rs completion-helper columns 2>/dev/null)
    
    # Handle comma-separated values and + prefix
    local current_word="${{cur}}"
    local prefix=""
    
    # Check if the current word starts with +
    if [[ "$current_word" == +* ]]; then
        prefix="+"
        current_word="${{current_word:1}}"
    fi
    
    # Find the last comma to determine what we're completing
    if [[ "$current_word" == *,* ]]; then
        # Extract everything before the last comma as prefix
        prefix="${{prefix}}${{current_word%,*}},"
        current_word="${{current_word##*,}}"
    fi
    
    # Generate completions by prefixing each column with the accumulated prefix
    local word_list=""
    for col in $columns; do
        if [[ "$col" == "$current_word"* ]]; then
            word_list="$word_list ${{prefix}}${{col}}"
        fi
    done
    
    COMPREPLY=($(compgen -W "$word_list" -- "${{cur}}"))
}}

# Override the generated completion for specific arguments
_vault_rs_override() {{
    local cur prev words cword
    _init_completion || return

    case "${{words[*]}}" in
        *"cert list"*|*"cert list-roles"*|*"cert create"*|*"cert sign"*|*"storage list"*)
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
                "--columns")
                    _vault_rs_complete_columns
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
        CompletionHelperCommands::Columns => {
            let columns = vec![
                "cn",
                "serial",
                "not_before",
                "not_after",
                "sans",
                "key_usage",
                "extended_key_usage",
                "ext_key_usage",
                "issuer",
                "pki_mount",
                "mount",
                "revoked",
                "r",
            ];
            output.print_list(&columns);
        }
    }

    Ok(())
}
