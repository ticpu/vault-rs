use crate::cert::show_certificate;
use crate::cli::args::*;
use crate::storage::local::LocalStorage;
use crate::utils::dns_discovery::get_vault_addr;
use crate::utils::errors::{Result, VaultCliError};
use crate::utils::output::OutputFormat;
use crate::vault::client::VaultClient;
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
    let output = OutputFormat::new(cli.raw, cli.json);

    // Ensure directories exist
    crate::utils::paths::VaultCliPaths::ensure_all_dirs()?;

    match cli.command {
        Commands::Auth { command } => crate::auth::handle_auth_commands(command, &output).await,
        Commands::Cert { command } => handle_cert_command(command, &output).await,
        Commands::Storage { command } => handle_storage_command(command, &output).await,
        Commands::Cache { command } => crate::cache::handle_cache_commands(command, &output).await,
        Commands::Completion { ref command } => {
            crate::cli::completions::handle_completion_command(command, &cli)
        }
        Commands::CompletionHelper { ref command } => {
            crate::cli::completions::handle_completion_helper_command(command, &output).await
        }
        Commands::Read { ref args } => handle_vault_command("read", args).await,
        Commands::Write { ref args } => handle_vault_command("write", args).await,
        Commands::Delete { ref args } => handle_vault_command("delete", args).await,
        Commands::List { ref args } => handle_vault_command("list", args).await,
        Commands::Patch { ref args } => handle_vault_command("patch", args).await,
        Commands::Unwrap { ref args } => handle_vault_command("unwrap", args).await,
        Commands::Status { ref args } => handle_vault_command("status", args).await,
        Commands::PathHelp { ref args } => handle_vault_command("path-help", args).await,
        Commands::Print { ref args } => handle_vault_command("print", args).await,
        Commands::VersionHistory { ref args } => {
            handle_vault_command("version-history", args).await
        }
        Commands::Audit { ref args } => handle_vault_command("audit", args).await,
        Commands::Debug { ref args } => handle_vault_command("debug", args).await,
        Commands::Events { ref args } => handle_vault_command("events", args).await,
        Commands::Kv { ref args } => handle_vault_command("kv", args).await,
        Commands::Lease { ref args } => handle_vault_command("lease", args).await,
        Commands::Monitor { ref args } => handle_vault_command("monitor", args).await,
        Commands::Namespace { ref args } => handle_vault_command("namespace", args).await,
        Commands::Operator { ref args } => handle_vault_command("operator", args).await,
        Commands::Pki { ref args } => handle_vault_command("pki", args).await,
        Commands::Plugin { ref args } => handle_vault_command("plugin", args).await,
        Commands::Policy { ref args } => handle_vault_command("policy", args).await,
        Commands::Secrets { ref args } => handle_vault_command("secrets", args).await,
        Commands::Ssh { ref args } => handle_vault_command("ssh", args).await,
        Commands::Token { ref args } => handle_vault_command("token", args).await,
        Commands::Transform { ref args } => handle_vault_command("transform", args).await,
        Commands::Transit { ref args } => handle_vault_command("transit", args).await,
    }
}

async fn handle_cert_command(command: CertCommands, output: &OutputFormat) -> Result<()> {
    let client = VaultClient::new().await;

    match command {
        CertCommands::List {
            pki_mount,
            columns,
            expiring_within,
            only_expired,
            exclude_expired,
            only_revoked,
            exclude_revoked,
            eku,
        } => {
            use crate::cert::{CertListFilter, CertificateListingService};

            let filter = match CertListFilter::new(
                expiring_within,
                only_expired,
                exclude_expired,
                only_revoked,
                exclude_revoked,
                eku,
            ) {
                Ok(filter) => filter,
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(2);
                }
            };
            let expiring_within_given = filter.is_expiring_within_active();

            match CertificateListingService::run_cert_list(
                pki_mount.as_deref(),
                columns,
                &filter,
                output,
            )
            .await
            {
                Ok(matched) if expiring_within_given && matched => std::process::exit(1),
                Ok(_) => Ok(()),
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(2);
                }
            }
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
        CertCommands::CaInfo {
            pki_mount_pos,
            pki_mount,
        } => {
            use crate::cert::show_ca_info;

            let mount = pki_mount.or(pki_mount_pos).ok_or_else(|| {
                VaultCliError::InvalidInput(
                    "PKI mount required: pass it positionally or with -m/--pki-mount".to_string(),
                )
            })?;

            show_ca_info(&client, &mount, output).await
        }
        CertCommands::Verify {
            certificate_file,
            against_ca,
            pki_mount,
            purpose,
        } => {
            use crate::cert::{verify_certificate, Purpose, VerifyRequest};

            let request = VerifyRequest {
                certificate_file,
                against_ca,
                pki_mount,
                purpose: purpose.map(|p| match p {
                    VerifyPurpose::ClientAuth => Purpose::ClientAuth,
                    VerifyPurpose::ServerAuth => Purpose::ServerAuth,
                }),
            };

            // A failed check is a verdict, not a malfunction: report it on the
            // exit code without the error formatting a fault would get.
            match verify_certificate(&client, request, output).await {
                Ok(true) => Ok(()),
                Ok(false) => std::process::exit(1),
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(2);
                }
            }
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
            pki_mount,
            cn,
            role,
            crypto,
            alt_names,
            ip_sans,
            ttl,
            no_store,
            export_plain,
            dry_run,
            yes,
        } => {
            use crate::cert::{create_certificate, CreateCertificateRequest};

            let request = CreateCertificateRequest {
                pki: pki_mount,
                cn: cn.clone(),
                role: role.clone(),
                crypto,
                alt_names,
                ip_sans,
                ttl,
                no_store,
                export_plain,
                dry_run,
                yes,
            };

            create_certificate(&client, request).await?;
            Ok(())
        }
        CertCommands::Sign {
            pki_mount,
            cn,
            csr_file,
            role,
            crypto,
            alt_names,
            ip_sans,
            ttl,
            no_store,
            export_plain,
            dry_run,
            yes,
        } => {
            use crate::cert::{sign_certificate_from_csr, CsrSignRequest};

            let request = CsrSignRequest {
                pki: pki_mount,
                cn,
                csr_file,
                role,
                crypto,
                alt_names,
                ip_sans,
                ttl,
                no_store,
                export_plain,
                dry_run,
                yes,
            };

            sign_certificate_from_csr(&client, request).await
        }
        CertCommands::Export {
            identifier,
            pki_mount,
            format,
            output,
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
        CertCommands::Show {
            identifier,
            pki_mount,
        } => match show_certificate(&client, &identifier, pki_mount.as_deref(), output).await {
            Ok(()) => Ok(()),
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        },
        CertCommands::ExportBySerial {
            serial,
            pki_mount,
            format,
            output,
            text,
        } => {
            // Use shared lookup function (serial is treated as identifier)
            use crate::cert::{
                export_certificate, find_certificate_by_identifier, ExportCertificateRequest,
            };
            match find_certificate_by_identifier(&client, &serial, pki_mount.as_deref()).await {
                Ok((pem, _found_serial, mount)) => {
                    let request = ExportCertificateRequest {
                        pem_data: pem,
                        mount,
                        identifier: serial.clone(),
                        format,
                        output_dir: Some(output),
                        no_passphrase: false, // export-by-serial has no --no-passphrase flag
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
        CertCommands::Revoke {
            identifier,
            pki_mount,
            yes,
        } => {
            use crate::cert::{revoke_certificate, RevokeRequest};

            let request = RevokeRequest {
                identifier: identifier.clone(),
                pki_mount: pki_mount.clone(),
                yes,
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
            role,
            columns,
        } => {
            use crate::cert::CertificateListingService;
            CertificateListingService::list_storage_certificates(
                &storage,
                pki,
                expired,
                expires_soon,
                role,
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
                    return Err(VaultCliError::InvalidInput(
                        "Invalid path structure. Expected: .../secrets/{pki_mount}/{cn}/file.enc"
                            .to_string(),
                    ));
                }
            } else {
                return Err(VaultCliError::InvalidInput(
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

async fn handle_vault_command(subcommand: &str, args: &[String]) -> Result<()> {
    let vault_addr = get_vault_addr().await?;
    crate::vault::wrapper::exec_vault_command(vault_addr, subcommand, args).await
}
