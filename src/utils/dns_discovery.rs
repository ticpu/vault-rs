use crate::utils::errors::{Result, VaultCliError};
use ordermap::OrderSet;
use serde::{Deserialize, Serialize};
use std::fs;
use trust_dns_resolver::TokioAsyncResolver;

#[derive(Serialize, Deserialize)]
struct CachedVaultAddr {
    address: String,
    cached_at: u64, // Unix timestamp
    ttl_seconds: u64,
}

/// Discover Vault server address using DNS SRV records with caching
pub async fn discover_vault_addr() -> Result<String> {
    // Check cache first
    if let Ok(cached_addr) = get_cached_vault_addr() {
        tracing::debug!("Using cached Vault address: {cached_addr}");
        return Ok(cached_addr);
    }

    // Parse search domains from /etc/resolv.conf
    let search_domains = parse_resolv_conf_search_domains()?;

    tracing::debug!(
        "Searching for Vault SRV records in domains: {:?}",
        search_domains
    );

    // Create DNS resolver with system configuration
    let resolver = TokioAsyncResolver::tokio_from_system_conf()
        .map_err(|e| VaultCliError::Config(format!("Failed to create DNS resolver: {e}")))?;

    // Try each search domain
    for domain in search_domains {
        let srv_name = format!("_vault._tcp.{domain}");
        tracing::debug!("Querying SRV record: {srv_name}");

        match resolver.srv_lookup(&srv_name).await {
            Ok(srv_response) => {
                // Use the first SRV record found
                if let Some(srv_record) = srv_response.iter().next() {
                    let host = srv_record.target().to_string();
                    let port = srv_record.port();

                    // Remove trailing dot from DNS name if present
                    let clean_host = host.trim_end_matches('.');
                    let vault_addr = format!("https://{clean_host}:{port}");

                    // Get TTL from the first record - use a reasonable default if not available
                    let ttl = srv_response
                        .as_lookup()
                        .records()
                        .first()
                        .map(|record| record.ttl())
                        .unwrap_or(300); // Default to 5 minutes if TTL unavailable

                    tracing::info!("Discovered Vault server via DNS: {vault_addr} (TTL: {ttl}s)");

                    // Cache the discovered address with its TTL
                    if let Err(e) = cache_vault_addr(&vault_addr, ttl) {
                        tracing::warn!("Failed to cache Vault address: {e}");
                    }

                    return Ok(vault_addr);
                }
            }
            Err(e) => {
                tracing::debug!("No SRV record found for {srv_name}: {e}");
                continue;
            }
        }
    }

    Err(VaultCliError::Config(
        "Could not discover Vault server via DNS. No SRV records found for _vault._tcp in any search domain.".to_string()
    ))
}

/// Parse search domains from /etc/resolv.conf
fn parse_resolv_conf_search_domains() -> Result<OrderSet<String>> {
    let resolv_conf = fs::read_to_string("/etc/resolv.conf")
        .map_err(|e| VaultCliError::Config(format!("Failed to read /etc/resolv.conf: {e}")))?;

    let mut search_domains = OrderSet::new();

    for line in resolv_conf.lines() {
        let line = line.trim();

        // Parse "search" lines
        if let Some(domains_str) = line.strip_prefix("search ") {
            let domains: Vec<String> = domains_str
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
            search_domains.extend(domains);
        }

        // Parse "domain" lines (legacy format)
        if let Some(domain) = line.strip_prefix("domain ") {
            search_domains.insert(domain.trim().to_string());
        }
    }

    if search_domains.is_empty() {
        return Err(VaultCliError::Config(
            "No search domains found in /etc/resolv.conf".to_string(),
        ));
    }

    tracing::debug!(
        "Parsed search domains from /etc/resolv.conf: {:?}",
        search_domains
    );
    Ok(search_domains)
}

/// Get cache file path for DNS-discovered Vault address
fn get_cache_file_path() -> Result<std::path::PathBuf> {
    Ok(crate::utils::paths::VaultCliPaths::runtime_dir()?.join("dns_vault_addr.yaml"))
}

/// Get cached Vault address if available and not expired based on DNS TTL
fn get_cached_vault_addr() -> Result<String> {
    let cache_file = get_cache_file_path()?;

    if !cache_file.exists() {
        return Err(VaultCliError::Config("No cached Vault address".to_string()));
    }

    let cache_content = fs::read_to_string(&cache_file)
        .map_err(|e| VaultCliError::Config(format!("Failed to read cached Vault address: {e}")))?;

    let cached: CachedVaultAddr = serde_yaml::from_str(&cache_content)
        .map_err(|e| VaultCliError::Config(format!("Failed to parse cached Vault address: {e}")))?;

    // Check if cache has expired based on DNS TTL
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let expires_at = cached.cached_at + cached.ttl_seconds;

    if now >= expires_at {
        let age = now - cached.cached_at;
        tracing::debug!(
            "DNS cache expired (age: {}s, TTL: {}s), will refresh",
            age,
            cached.ttl_seconds
        );
        return Err(VaultCliError::Config(
            "Cache expired based on DNS TTL".to_string(),
        ));
    }

    let remaining_ttl = expires_at - now;
    tracing::debug!(
        "Using cached Vault address (TTL remaining: {}s)",
        remaining_ttl
    );

    Ok(cached.address)
}

/// Cache the discovered Vault address with its DNS TTL
fn cache_vault_addr(vault_addr: &str, ttl_seconds: u32) -> Result<()> {
    let cache_file = get_cache_file_path()?;

    // Ensure cache directory exists
    if let Some(parent) = cache_file.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| VaultCliError::Config(format!("Failed to create cache directory: {e}")))?;
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let cached = CachedVaultAddr {
        address: vault_addr.to_string(),
        cached_at: now,
        ttl_seconds: ttl_seconds as u64,
    };

    let cache_content = serde_yaml::to_string(&cached)
        .map_err(|e| VaultCliError::Config(format!("Failed to serialize cache data: {e}")))?;

    fs::write(&cache_file, cache_content)
        .map_err(|e| VaultCliError::Config(format!("Failed to cache Vault address: {e}")))?;

    tracing::debug!(
        "Cached Vault address to: {} (TTL: {}s)",
        cache_file.display(),
        ttl_seconds
    );
    Ok(())
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_parse_resolv_conf_search_domains() {
        // This test would require mocking the file system
        // For now, we'll skip it and rely on integration testing
    }
}
