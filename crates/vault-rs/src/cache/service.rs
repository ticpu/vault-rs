use crate::cli::args::CacheCommands;
use crate::utils::errors::Result;
use crate::utils::output::OutputFormat;

pub async fn handle_cache_commands(command: CacheCommands, output: &OutputFormat) -> Result<()> {
    use crate::cert::CertificateService;
    let cert_service = CertificateService::new().await?;

    match command {
        CacheCommands::Status { allow_partial } => {
            show_cache_status(&cert_service, allow_partial, output).await
        }
        CacheCommands::Clear { pki } => clear_cache(&cert_service, pki).await,
    }
}

/// The per-mount counts are what this command was asked for, so they go to
/// stdout through `OutputFormat`; the totals above them are for a person.
async fn show_cache_status(
    cert_service: &crate::cert::CertificateService,
    allow_partial: bool,
    output: &OutputFormat,
) -> Result<()> {
    let mut stats = cert_service.get_cache_stats()?.resolve(allow_partial)?;

    if stats.is_empty() {
        eprintln!("No cache entries found");
        return Ok(());
    }

    stats.sort_by(|a, b| a.0.cmp(&b.0));

    let total: usize = stats
        .iter()
        // discard-ok: a mount whose count could not be read is empty here, and
        // must not contribute a number to the total
        .filter_map(|(_, count)| count.parse::<usize>().ok())
        .sum();
    eprintln!("{} PKI mounts cached, {total} certificates", stats.len());

    output.print_key_value(&stats);
    Ok(())
}

async fn clear_cache(
    cert_service: &crate::cert::CertificateService,
    pki: Option<String>,
) -> Result<()> {
    match pki {
        Some(mount) => {
            cert_service.clear_cache(&mount)?;
            eprintln!("Cleared cache for PKI mount: {mount}");
        }
        None => {
            let cleared_count = cert_service.clear_all_cache()?;
            eprintln!("Cleared cache for {cleared_count} PKI mounts");
            eprintln!("Certificates will be fetched from Vault on next access");
        }
    }
    Ok(())
}
