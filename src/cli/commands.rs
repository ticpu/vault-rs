use crate::cert::show_certificate;
use crate::cli::args::*;
use crate::storage::local::LocalStorage;
use crate::utils::dns_discovery::get_vault_addr;
use crate::utils::errors::VaultCliError;
use crate::utils::output::OutputFormat;
use crate::utils::partial::{Incomplete, Partial};
use crate::utils::PROGRAM_NAME;
use crate::vault::client::VaultClient;
use anyhow::{Context, Result};
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
        Commands::Auth { command } => crate::auth::handle_auth_commands(command, &output)
            .await
            .context("auth"),
        Commands::Cert { command } => handle_cert_command(command, &output).await,
        Commands::Storage { command } => handle_storage_command(command, &output).await,
        Commands::Cache { command } => crate::cache::handle_cache_commands(command, &output)
            .await
            .context("cache"),
        Commands::Completion { ref command } => {
            crate::cli::completions::handle_completion_command(command, &cli)
                .context("generating the completion script")
        }
        Commands::CompletionHelper { ref command } => {
            crate::cli::completions::handle_completion_helper_command(command, &output).await?;
            Ok(())
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
            allow_partial,
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
                    eprintln!("Error: {:#}", anyhow::Error::from(e));
                    std::process::exit(2);
                }
            };
            let expiring_within_given = filter.is_expiring_within_active();

            match CertificateListingService::run_cert_list(
                pki_mount.as_deref(),
                columns,
                &filter,
                allow_partial,
                output,
            )
            .await
            {
                Ok(matched) if expiring_within_given && matched => std::process::exit(1),
                Ok(_) => Ok(()),
                Err(e) => {
                    eprintln!("Error: {:#}", anyhow::Error::from(e));
                    std::process::exit(2);
                }
            }
        }
        CertCommands::ListMounts { allow_partial } => {
            let client = VaultClient::new().await?;
            let pki_mounts = client.list_pki_mounts().await?;

            // The mount name read fine; only the secondary query can fail, so
            // the row stays and the cell is left empty rather than filled with
            // a crypto type nobody detected.
            let mut mount_data = Partial::new();
            for mount in pki_mounts {
                match client.detect_crypto_type(&mount).await {
                    Ok(crypto_type) => mount_data.push((mount, crypto_type)),
                    Err(e) => {
                        mount_data.fail(Incomplete::unread_field(&mount, "crypto type", e));
                        mount_data.push((mount, String::new()));
                    }
                }
            }

            output.print_key_value(&mount_data.resolve(allow_partial)?);
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

            let client = VaultClient::new().await?;
            show_ca_info(&client, &mount, output)
                .await
                .with_context(|| format!("reading the CA of mount '{mount}'"))
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

            // Vault is contacted only to fetch a mount's CA. Verifying against
            // a file must keep working while Vault is down, which is when an
            // operator reaches for a local anchor; and a connection failure has
            // to reach the exit-2 arm below rather than propagate as exit 1,
            // where it would be indistinguishable from a failed check.
            let verdict = async {
                let client = match request.pki_mount {
                    Some(_) => Some(VaultClient::new().await?),
                    None => None,
                };
                verify_certificate(client.as_ref(), request, output).await
            }
            .await;

            // A failed check is a verdict, not a malfunction: report it on the
            // exit code without the error formatting a fault would get.
            match verdict {
                Ok(true) => Ok(()),
                Ok(false) => std::process::exit(1),
                Err(e) => {
                    eprintln!("Error: {:#}", anyhow::Error::from(e));
                    std::process::exit(2);
                }
            }
        }
        CertCommands::ListRoles { pki_mount } => {
            let client = VaultClient::new().await?;

            // List available roles in PKI mount - UNIX friendly output
            match client.list_roles(&pki_mount).await {
                Ok(roles) => {
                    if !roles.is_empty() {
                        output.print_list(&roles);
                    }
                }
                Err(VaultCliError::Auth(e)) => {
                    eprintln!("Error: cannot list roles in PKI mount '{pki_mount}': {e}");
                    eprintln!("Your token may lack permission; check the mounts you can reach with: {PROGRAM_NAME} cert list-mounts");
                    std::process::exit(2);
                }
                Err(e) => return Err(e.into()),
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

            let client = VaultClient::new().await?;
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

            let client = VaultClient::new().await?;
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

            sign_certificate_from_csr(&client, request)
                .await
                .context("signing the certificate request")
        }
        CertCommands::InspectCsr {
            file,
            pki_mount,
            role,
        } => {
            use crate::cert::{inspect_csr, InspectCsrRequest};

            // clap requires -m/--pki-mount and --role together, so a client
            // is only ever needed when both are present.
            let client = if pki_mount.is_some() {
                Some(VaultClient::new().await?)
            } else {
                None
            };
            let request = InspectCsrRequest {
                csr_file: file,
                pki_mount,
                role,
            };

            inspect_csr(client.as_ref(), request)
                .await
                .context("inspecting the certificate request")
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
            let client = VaultClient::new().await?;
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
                Err(e) => return Err(e).context(format!("exporting '{identifier}'")),
            }
            Ok(())
        }
        CertCommands::Show {
            identifier,
            pki_mount,
        } => {
            let client = VaultClient::new().await?;
            show_certificate(&client, &identifier, pki_mount.as_deref(), output)
                .await
                .with_context(|| format!("showing '{identifier}'"))
        }
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
            let client = VaultClient::new().await?;
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
                Err(e) => return Err(e).context(format!("exporting serial '{serial}'")),
            }
            Ok(())
        }
        CertCommands::Revoke {
            identifier,
            pki_mount,
            yes,
        } => {
            use crate::cert::{revoke_certificate, RevokeRequest};

            let client = VaultClient::new().await?;
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
    let storage = LocalStorage::new().await?;

    match command {
        StorageCommands::List {
            pki,
            expired,
            expires_soon,
            role,
            columns,
            allow_partial,
        } => {
            use crate::cert::{CertificateListingService, StorageListRequest};
            CertificateListingService::list_storage_certificates(
                &storage,
                StorageListRequest {
                    pki,
                    expired,
                    expires_soon,
                    role,
                    columns,
                    allow_partial,
                },
                output,
            )
            .await
            .context("listing local storage")
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
                    )
                    .into());
                }
            } else {
                return Err(VaultCliError::InvalidInput(
                    "Path must contain 'secrets' directory. Expected: .../secrets/{pki_mount}/{cn}/file.enc".to_string()
                ).into());
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
    crate::vault::wrapper::exec_vault_command(vault_addr, subcommand, args)
        .await
        .with_context(|| format!("vault {subcommand}"))
}
