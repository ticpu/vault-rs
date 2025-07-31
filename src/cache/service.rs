use crate::cli::args::CacheCommands;
use crate::utils::errors::Result;
use crate::utils::output::OutputFormat;

pub async fn handle_cache_commands(command: CacheCommands, _output: &OutputFormat) -> Result<()> {
    use crate::cert::CertificateService;
    let cert_service = CertificateService::new().await?;

    match command {
        CacheCommands::Status => show_cache_status(&cert_service).await,
        CacheCommands::Clear { pki } => clear_cache(&cert_service, pki).await,
    }
}

async fn show_cache_status(cert_service: &crate::cert::CertificateService) -> Result<()> {
    let stats = cert_service.get_cache_stats()?;
    let total_entries: usize = stats.values().sum();

    if stats.is_empty() {
        eprintln!("No cache entries found");
        return Ok(());
    }

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
