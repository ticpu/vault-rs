use crate::cli::args::*;
use crate::storage::local::LocalStorage;
use crate::utils::errors::{Result, VaultCliError};
use crate::utils::output::OutputFormat;
use crate::vault::{auth::VaultAuth, client::VaultClient};
use clap::CommandFactory;
use clap_complete::{generate, Shell};
use std::env;
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
                            let client = VaultClient::new(vault_addr.clone());

                            // Test sys/mounts access
                            match client.get(&token, "sys/mounts").await {
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
            let token = auth.get_token().await?;
            let encryption_manager = crate::crypto::encryption::EncryptionManager::new(vault_addr);
            encryption_manager.init_encryption_key(&token).await?;
            println!("Encryption key initialized in personal vault");
            Ok(())
        }
        AuthCommands::ListSecrets => {
            let token = auth.get_token().await?;
            let client = VaultClient::new(vault_addr.clone());

            match client.get(&token, "sys/mounts").await {
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
    let vault_addr = get_vault_addr().await?;
    let client = VaultClient::new(vault_addr.clone());
    let auth = VaultAuth::new(vault_addr.clone());
    let token = auth.get_token().await?;
    tracing::debug!("Using token: {}***", &token[..8]);

    match command {
        CertCommands::List { pki_mount, columns } => {
            use crate::cert::{CertificateColumn, CertificateService};

            // Set default columns based on whether listing all mounts or specific mount
            let default_columns = if pki_mount.is_some() {
                vec!["cn", "not_after", "extended_key_usage", "sans"]
            } else {
                vec!["pki_mount", "cn", "not_after", "extended_key_usage", "sans"]
            };

            // Parse columns with support for + prefix (append to defaults)
            let columns = if let Some(columns_str) = columns {
                if columns_str.starts_with('+') {
                    // Append mode: start with defaults and add specified columns
                    let mut result_columns = default_columns;
                    let additional_cols: Vec<&str> = columns_str[1..] // Remove the + prefix
                        .split(',')
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                        .collect();
                    result_columns.extend(additional_cols);

                    let parsed: Result<Vec<CertificateColumn>> = result_columns
                        .into_iter()
                        .map(|col| {
                            col.parse::<CertificateColumn>()
                                .map_err(VaultCliError::InvalidInput)
                        })
                        .collect();
                    parsed?
                } else {
                    // Regular mode: use specified columns only
                    let parsed: Result<Vec<CertificateColumn>> = columns_str
                        .split(',')
                        .map(|col| {
                            col.trim()
                                .parse::<CertificateColumn>()
                                .map_err(VaultCliError::InvalidInput)
                        })
                        .collect();
                    parsed?
                }
            } else {
                // No columns specified: use defaults
                let parsed: Result<Vec<CertificateColumn>> = default_columns
                    .into_iter()
                    .map(|col| {
                        col.parse::<CertificateColumn>()
                            .map_err(VaultCliError::InvalidInput)
                    })
                    .collect();
                parsed?
            };

            // Create certificate service and get metadata
            let cert_service = CertificateService::new(vault_addr.clone())?;

            let certificates = match cert_service
                .list_certificates_with_metadata(&token, pki_mount.as_deref())
                .await
            {
                Ok(certs) => certs,
                Err(VaultCliError::Auth(_)) if pki_mount.is_some() => {
                    let mount = pki_mount.as_ref().unwrap();
                    eprintln!("Error: Access denied - your token may not have permission to list certificates in PKI mount '{mount}'");
                    eprintln!("Try checking available PKI mounts with: vault-rs cert list-mounts");
                    std::process::exit(1);
                }
                Err(e) => return Err(e),
            };

            if certificates.is_empty() {
                // No certificates found - still output nothing for UNIX compatibility
                return Ok(());
            }

            // UNIX-friendly output: one line per certificate with specified columns
            for cert in certificates {
                let values: Vec<String> = columns
                    .iter()
                    .map(|col| cert.get_column_value(col))
                    .collect();
                println!("{}", values.join("\t"));
            }
            Ok(())
        }
        CertCommands::ListMounts => {
            // List all PKI mounts with crypto types - UNIX friendly output
            let pki_mounts = client.list_pki_mounts(&token).await?;

            let mut mount_data = Vec::new();
            for mount in pki_mounts {
                let crypto_type = client
                    .detect_crypto_type(&token, &mount)
                    .await
                    .unwrap_or_else(|_| "unknown".to_string());
                mount_data.push((mount, crypto_type));
            }

            output.print_key_value(&mount_data);
            Ok(())
        }
        CertCommands::ListRoles { pki_mount } => {
            // List available roles in PKI mount - UNIX friendly output
            match client.list_roles(&token, &pki_mount).await {
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

            create_certificate(&client, &token, request).await?;
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

            sign_certificate_from_csr(&client, &token, request).await
        }
        CertCommands::Export {
            identifier,
            pki_mount,
            format,
            output,
            decrypt: _,
            no_passphrase,
        } => {
            use crate::cert::{export_certificate, find_certificate_by_identifier};
            match find_certificate_by_identifier(&client, &token, &identifier, pki_mount.as_deref())
                .await
            {
                Ok((pem, _serial, mount)) => {
                    export_certificate(
                        &client,
                        &token,
                        &pem,
                        &mount,
                        &identifier,
                        &format,
                        output.as_deref(),
                        no_passphrase,
                    )
                    .await?;
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
            match find_certificate_by_identifier(&client, &token, &identifier, pki_mount.as_deref())
                .await
            {
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
            use crate::cert::{export_certificate, find_certificate_by_identifier};
            match find_certificate_by_identifier(&client, &token, &serial, None).await {
                Ok((pem, _found_serial, mount)) => {
                    export_certificate(
                        &client,
                        &token,
                        &pem,
                        &mount,
                        &serial,
                        &format,
                        Some(&output),
                        false, // Extract command defaults to no passphrase
                    )
                    .await?;
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

            revoke_certificate(&client, &token, request).await?;
            Ok(())
        }
    }
}

async fn handle_storage_command(command: StorageCommands, output: &OutputFormat) -> Result<()> {
    let vault_addr = get_vault_addr().await?;
    let auth = VaultAuth::new(vault_addr.clone());
    let token = auth.get_token().await?;
    let storage = LocalStorage::new(vault_addr);

    match command {
        StorageCommands::List {
            pki,
            expired,
            expires_soon,
        } => {
            let certificates = storage.list_certificates(&token).await?;

            let filtered_certs: Vec<_> = certificates
                .into_iter()
                .filter(|cert| {
                    // Filter by PKI mount if specified
                    if let Some(ref pki_filter) = pki {
                        if cert.pki_mount != *pki_filter {
                            return false;
                        }
                    }

                    // Filter by expiration status
                    if expired && !cert.meta.is_expired() {
                        return false;
                    }

                    // Filter by expires soon
                    if let Some(days) = &expires_soon {
                        let days_u32 = days.parse::<u32>().unwrap_or(30);
                        if !cert.meta.expires_soon(days_u32) {
                            return false;
                        }
                    }

                    true
                })
                .collect();

            // Use OutputFormat for structured data output
            let table_data: Vec<Vec<String>> = filtered_certs
                .into_iter()
                .map(|cert_storage| {
                    let cert = cert_storage.meta;
                    let status = if cert.is_expired() {
                        "EXPIRED"
                    } else {
                        "ACTIVE"
                    };
                    vec![
                        cert.cn,
                        cert_storage.pki_mount,
                        cert.serial,
                        cert.expires.format("%Y-%m-%d %H:%M").to_string(),
                        status.to_string(),
                    ]
                })
                .collect();

            output.print_table(&table_data);
            Ok(())
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
        StorageCommands::Cleanup { expired_only } => {
            println!("Cleanup certificates - Expired only: {expired_only}");
            // TODO: Implement cleanup
            Ok(())
        }
        StorageCommands::Backup { output_file } => {
            println!("Backup to: {output_file}");
            // TODO: Implement backup
            Ok(())
        }
        StorageCommands::Restore { backup_file } => {
            println!("Restore from: {backup_file}");
            // TODO: Implement restore
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
            let decrypted_data = storage.decrypt_file(&token, &context, path).await?;

            let content = String::from_utf8_lossy(&decrypted_data);
            println!("{content}");
            Ok(())
        }
    }
}

async fn handle_cache_command(command: CacheCommands, _output: &OutputFormat) -> Result<()> {
    use crate::cert::CertificateService;

    let vault_addr = get_vault_addr().await?;
    let auth = VaultAuth::new(vault_addr.clone());
    let _token = auth.get_token().await?;
    let cert_service = CertificateService::new(vault_addr.clone())?;

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
    let vault_addr = get_vault_addr().await?;
    let auth = VaultAuth::new(vault_addr.clone());
    let client = VaultClient::new(vault_addr.clone());

    // Silently fail if no token - completion should not show errors
    let token = match auth.get_token().await {
        Ok(token) => token,
        Err(_) => return Ok(()),
    };

    match command {
        CompletionHelperCommands::PkiMounts => {
            if let Ok(pki_mounts) = client.list_pki_mounts(&token).await {
                output.print_list(&pki_mounts);
            }
        }
        CompletionHelperCommands::Roles { pki_mount } => {
            if let Ok(roles) = client.list_roles(&token, pki_mount).await {
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

async fn get_vault_addr() -> Result<String> {
    // First try environment variable
    if let Ok(vault_addr) = env::var("VAULT_ADDR") {
        return Ok(vault_addr);
    }

    // Fall back to DNS discovery
    tracing::info!("VAULT_ADDR not set, attempting DNS discovery...");
    crate::utils::dns_discovery::discover_vault_addr().await
}
