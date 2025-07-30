use crate::cli::args::*;
use crate::storage::local::LocalStorage;
use crate::utils::dns_discovery::get_vault_addr;
use crate::utils::errors::{Result, VaultCliError};
use crate::utils::output::OutputFormat;
use crate::vault::{auth::VaultAuth, client::VaultClient};
use clap::CommandFactory;
use clap_complete::{generate, Shell};
use std::io;

pub async fn handle_command(cli: Cli) -> Result<()> {
    // Initialize logging - always to stderr
    if !cli.quiet {
        let log_level = match cli.verbose {
            0 => "vault_rs=warn",  // Default: warnings only
            1 => "vault_rs=info",  // -v: info level
            2 => "vault_rs=debug", // -vv: debug level
            _ => "vault_rs=trace", // -vvv+: trace level
        };

        tracing_subscriber::fmt()
            .with_writer(io::stderr)
            .with_env_filter(log_level)
            .init();
    }

    // Create output formatter
    let output = OutputFormat::new(cli.raw);

    // Ensure directories exist
    crate::utils::paths::VaultCliPaths::ensure_all_dirs()?;

    match cli.command {
        Commands::Auth { command } => handle_auth_command(command, &output).await,
        Commands::Cert { command } => handle_cert_command(command, &output).await,
        Commands::Storage { command } => handle_storage_command(command, &output).await,
        Commands::Cache { command } => handle_cache_command(command, &output).await,
        Commands::Completion { ref command } => handle_completion_command(command, &cli),
        Commands::CompletionHelper { ref command } => {
            handle_completion_helper_command(command, &output).await
        }
        Commands::Secrets { ref args } => handle_vault_command("secrets", args).await,
        Commands::Operator { ref args } => handle_vault_command("operator", args).await,
    }
}

async fn handle_auth_command(command: AuthCommands, output: &OutputFormat) -> Result<()> {
    let vault_addr = get_vault_addr().await?;
    let auth = VaultAuth::new(vault_addr.clone());

    match command {
        AuthCommands::Login { method, username } => {
            let token = if let Some(user) = username {
                let password = rpassword::prompt_password("Password: ")
                    .map_err(|e| VaultCliError::Auth(format!("Failed to read password: {e}")))?;

                match method.as_str() {
                    "ldap" => auth.login_ldap(&user, &password).await?,
                    "userpass" => auth.login_userpass(&user, &password).await?,
                    _ => {
                        return Err(VaultCliError::Auth(format!(
                            "Unsupported auth method: {method}"
                        )))
                    }
                }
            } else {
                auth.interactive_login(Some(method)).await?
            };

            println!("Successfully logged in with token: {}***", &token[..8]);
            Ok(())
        }
        AuthCommands::Logout => {
            auth.logout().await?;
            println!("Successfully logged out");
            Ok(())
        }
        AuthCommands::Status => {
            match auth.get_token().await {
                Ok(token) => {
                    match auth.get_token_info(&token).await {
                        Ok(info) => {
                            println!("Token status: Valid");
                            if let Some(data) = info.get("data") {
                                if let Some(display_name) = data.get("display_name") {
                                    println!("User: {display_name}");
                                }
                                if let Some(policies) = data.get("policies") {
                                    println!("Policies: {policies}");
                                }
                                if let Some(ttl) = data.get("ttl") {
                                    println!("TTL: {ttl} seconds");
                                }
                                if let Some(entity_id) = data.get("entity_id") {
                                    println!("Entity ID: {entity_id}");
                                }
                            }

                            // Check specific capabilities
                            println!("\nChecking permissions:");
                            // Test sys/mounts access
                            let test_client = VaultClient::new().await;
                            match test_client.get("sys/mounts").await {
                                Ok(_) => println!("✓ Can list secret engines"),
                                Err(_) => println!("✗ Cannot list secret engines (sys/mounts)"),
                            }
                        }
                        Err(_) => println!("Token status: Invalid"),
                    }
                }
                Err(_) => println!("No active token found"),
            }
            Ok(())
        }
        AuthCommands::InitEncryption => {
            let encryption_manager = crate::crypto::encryption::EncryptionManager::new().await;
            encryption_manager.init_encryption_key().await?;
            println!("Encryption key initialized in personal vault");
            Ok(())
        }
        AuthCommands::ListSecrets => {
            let client = VaultClient::new().await;

            match client.get("sys/mounts").await {
                Ok(mounts) => {
                    if let Some(data) = mounts.get("data").and_then(|d| d.as_object()) {
                        let mut mount_list: Vec<_> = data.iter().collect();
                        mount_list.sort_by_key(|(path, _)| *path);

                        let table_data: Vec<Vec<String>> = mount_list
                            .iter()
                            .filter_map(|(mount_path, mount_info)| {
                                mount_info
                                    .get("type")
                                    .and_then(|t| t.as_str())
                                    .map(|mount_type| {
                                        let version = if mount_type == "kv" {
                                            mount_info
                                                .get("options")
                                                .and_then(|opts| opts.get("version"))
                                                .and_then(|v| v.as_str())
                                                .unwrap_or("1")
                                        } else {
                                            ""
                                        };

                                        let mount_display =
                                            if mount_type == "kv" && !version.is_empty() {
                                                format!("{mount_type} v{version}")
                                            } else {
                                                mount_type.to_string()
                                            };

                                        vec![
                                            mount_path.trim_end_matches('/').to_string(),
                                            mount_display,
                                        ]
                                    })
                            })
                            .collect();

                        output.print_table(&table_data);
                    }
                }
                Err(_) => {
                    eprintln!("Cannot list secret engines - insufficient permissions");
                    std::process::exit(1);
                }
            }
            Ok(())
        }
    }
}

async fn handle_cert_command(command: CertCommands, output: &OutputFormat) -> Result<()> {
    let client = VaultClient::new().await;

    match command {
        CertCommands::List { pki_mount, columns } => {
            use crate::cert::{CertificateListingService, CertificateService};
            let cert_service = CertificateService::new().await?;
            CertificateListingService::list_vault_certificates(
                &cert_service,
                pki_mount.as_deref(),
                columns,
                output,
            )
            .await
        }
        CertCommands::ListMounts => {
            // List all PKI mounts with crypto types - UNIX friendly output
            let pki_mounts = client.list_pki_mounts().await?;

            let mut mount_data = Vec::new();
            for mount in pki_mounts {
                let crypto_type = client
                    .detect_crypto_type(&mount)
                    .await
                    .unwrap_or_else(|_| "unknown".to_string());
                mount_data.push((mount, crypto_type));
            }

            output.print_key_value(&mount_data);
            Ok(())
        }
        CertCommands::ListRoles { pki_mount } => {
            // List available roles in PKI mount - UNIX friendly output
            match client.list_roles(&pki_mount).await {
                Ok(roles) => {
                    if !roles.is_empty() {
                        output.print_list(&roles);
                    }
                }
                Err(VaultCliError::Auth(_)) => {
                    eprintln!("Error: Access denied - your token may not have permission to list roles in PKI mount '{pki_mount}'");
                    eprintln!("Try checking available PKI mounts with: vault-rs cert list-mounts");
                    std::process::exit(1);
                }
                Err(e) => return Err(e),
            }
            Ok(())
        }
        CertCommands::Create {
            pki,
            cn,
            role,
            crypto,
            alt_names,
            ip_sans,
            ttl,
            no_store,
            export_plain,
        } => {
            use crate::cert::{create_certificate, CreateCertificateRequest};

            let request = CreateCertificateRequest {
                pki: pki.clone(),
                cn: cn.clone(),
                role: role.clone(),
                crypto,
                alt_names,
                ip_sans,
                ttl,
                no_store,
                export_plain,
            };

            create_certificate(&client, request).await?;
            Ok(())
        }
        CertCommands::Sign {
            pki,
            cn,
            csr_file,
            role,
            crypto,
            alt_names,
            ip_sans,
            ttl,
            no_store,
            export_plain,
        } => {
            use crate::cert::{sign_certificate_from_csr, CsrSignRequest};

            let request = CsrSignRequest {
                pki,
                cn,
                csr_file,
                role,
                crypto,
                alt_names,
                ip_sans,
                ttl,
                no_store,
                export_plain,
            };

            sign_certificate_from_csr(&client, request).await
        }
        CertCommands::Export {
            identifier,
            pki_mount,
            format,
            output,
            decrypt: _,
            no_passphrase,
            text,
        } => {
            use crate::cert::{
                export_certificate, find_certificate_by_identifier, ExportCertificateRequest,
            };
            match find_certificate_by_identifier(&client, &identifier, pki_mount.as_deref()).await {
                Ok((pem, _serial, mount)) => {
                    let request = ExportCertificateRequest {
                        pem_data: pem,
                        mount,
                        identifier: identifier.clone(),
                        format,
                        output_dir: output,
                        no_passphrase,
                        text,
                    };
                    export_certificate(&client, request).await?;
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
            Ok(())
        }
        CertCommands::Extract {
            json_file,
            cn: _,
            pki_mount: _,
        } => {
            println!("Extract from JSON file: {json_file}");
            // TODO: Implement extract
            Ok(())
        }
        CertCommands::Show {
            identifier,
            pki_mount,
        } => {
            // Use shared lookup function to find certificate
            use crate::cert::find_certificate_by_identifier;
            match find_certificate_by_identifier(&client, &identifier, pki_mount.as_deref()).await {
                Ok((pem, _serial, mount)) => {
                    // Parse certificate to extract details for UNIX-friendly output
                    use crate::cert::CertificateParser;
                    match CertificateParser::parse_pem(&pem, &mount) {
                        Ok(metadata) => {
                            // UNIX-friendly output: tab-separated key info
                            println!(
                                "{}\t{}\t{}\t{}\t{}\t{}",
                                metadata.cn,
                                metadata.serial,
                                metadata.not_before.format("%Y-%m-%d %H:%M"),
                                metadata.not_after.format("%Y-%m-%d %H:%M"),
                                metadata.sans.join(","),
                                mount
                            );
                        }
                        Err(e) => {
                            eprintln!("Error parsing certificate: {e}");
                            std::process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
            Ok(())
        }
        CertCommands::ExportBySerial {
            serial,
            format,
            output,
        } => {
            // Use shared lookup function (serial is treated as identifier)
            use crate::cert::{
                export_certificate, find_certificate_by_identifier, ExportCertificateRequest,
            };
            match find_certificate_by_identifier(&client, &serial, None).await {
                Ok((pem, _found_serial, mount)) => {
                    let request = ExportCertificateRequest {
                        pem_data: pem,
                        mount,
                        identifier: serial.clone(),
                        format,
                        output_dir: Some(output),
                        no_passphrase: false, // Extract command defaults to no passphrase
                        text: false,          // ExportBySerial doesn't support --text flag
                    };
                    export_certificate(&client, request).await?;
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
            Ok(())
        }
        CertCommands::FindSerial { serial } => {
            println!("Find certificate by serial: {serial}");
            // TODO: Implement find serial
            Ok(())
        }
        CertCommands::Revoke {
            identifier,
            pki_mount,
        } => {
            use crate::cert::{revoke_certificate, RevokeRequest};

            let request = RevokeRequest {
                identifier: identifier.clone(),
                pki_mount: pki_mount.clone(),
            };

            revoke_certificate(&client, request).await?;
            Ok(())
        }
    }
}

async fn handle_storage_command(command: StorageCommands, output: &OutputFormat) -> Result<()> {
    let storage = LocalStorage::new().await;

    match command {
        StorageCommands::List {
            pki,
            expired,
            expires_soon,
            columns,
        } => {
            use crate::cert::CertificateListingService;
            CertificateListingService::list_storage_certificates(
                &storage,
                pki,
                expired,
                expires_soon,
                columns,
                output,
            )
            .await
        }
        StorageCommands::Show { cn, pki_mount } => {
            println!("Show stored certificate - CN: {cn}, PKI: {pki_mount:?}");
            // TODO: Implement storage show
            Ok(())
        }
        StorageCommands::Remove { cn, pki_mount } => {
            println!("Remove stored certificate - CN: {cn}, PKI: {pki_mount:?}");
            // TODO: Implement storage remove
            Ok(())
        }
        StorageCommands::Decrypt { file_path } => {
            use std::path::Path;

            let path = Path::new(&file_path);
            if !path.exists() {
                eprintln!("File not found: {file_path}");
                return Ok(());
            }

            // Extract PKI mount and CN from path structure: .../secrets/{pki_mount}/{cn}/file.enc
            let path_components: Vec<&str> = path
                .components()
                .filter_map(|c| c.as_os_str().to_str())
                .collect();

            let (pki_mount, cn) = if let Some(secrets_idx) =
                path_components.iter().position(|&x| x == "secrets")
            {
                if secrets_idx + 2 < path_components.len() {
                    (
                        path_components[secrets_idx + 1],
                        path_components[secrets_idx + 2],
                    )
                } else {
                    return Err(crate::utils::errors::VaultCliError::InvalidInput(
                        "Invalid path structure. Expected: .../secrets/{pki_mount}/{cn}/file.enc"
                            .to_string(),
                    ));
                }
            } else {
                return Err(crate::utils::errors::VaultCliError::InvalidInput(
                    "Path must contain 'secrets' directory. Expected: .../secrets/{pki_mount}/{cn}/file.enc".to_string()
                ));
            };

            let context = format!("cert-{pki_mount}-{cn}");
            let decrypted_data = storage.decrypt_file(&context, path).await?;

            let content = String::from_utf8_lossy(&decrypted_data);
            println!("{content}");
            Ok(())
        }
    }
}

async fn handle_cache_command(command: CacheCommands, _output: &OutputFormat) -> Result<()> {
    use crate::cert::CertificateService;
    let cert_service = CertificateService::new().await?;

    match command {
        CacheCommands::Status => {
            let stats = cert_service.get_cache_stats()?;
            let total_entries: usize = stats.values().sum();

            if stats.is_empty() {
                eprintln!("No cache entries found");
            } else {
                eprintln!("Cache Statistics:");
                eprintln!("Total certificates cached: {total_entries}");
                eprintln!("PKI mounts cached: {}", stats.len());
                eprintln!();
                eprintln!("Per-mount breakdown:");

                let mut sorted_stats: Vec<_> = stats.into_iter().collect();
                sorted_stats.sort_by(|a, b| a.0.cmp(&b.0));

                for (mount, count) in sorted_stats {
                    eprintln!("  {mount}: {count} certificates");
                }
            }
            Ok(())
        }
        CacheCommands::Clear { pki } => {
            if let Some(mount) = pki {
                cert_service.clear_cache(&mount)?;
                eprintln!("Cleared cache for PKI mount: {mount}");
            } else {
                // Clear all caches
                let cleared_count = cert_service.clear_all_cache()?;
                eprintln!("Cleared cache for {cleared_count} PKI mounts");
                eprintln!("Certificates will be fetched from Vault on next access");
            }
            Ok(())
        }
    }
}

fn handle_completion_command(command: &CompletionCommands, _cli: &Cli) -> Result<()> {
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
                "list"|"list-roles"|"create"|"sign")
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

async fn handle_completion_helper_command(
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

async fn handle_vault_command(subcommand: &str, args: &[String]) -> Result<()> {
    let vault_addr = get_vault_addr().await?;
    crate::vault::wrapper::exec_vault_command(vault_addr, subcommand, args).await
}
