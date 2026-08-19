//! Finding the Vault address: an environment variable, an SRV record, or one
//! the caller states outright.
//!
//! Which of those a session consults is an [`Address`] the caller passes, so
//! none of them is reached without being asked for. A discovered address may be
//! cached for its record's TTL in a file the caller names.

use crate::error::{Error, Result};
use hickory_resolver::proto::rr::RData;
use hickory_resolver::TokioResolver;
use ordermap::OrderSet;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::{env, fs};

#[derive(Serialize, Deserialize)]
struct CachedVaultAddr {
    address: String,
    cached_at: u64, // Unix timestamp
    ttl_seconds: u64,
}

/// Where a session looks for the Vault address, in the order it looks.
///
/// Resolved per session rather than once per process: following an artifact
/// back to the cluster that sealed it should not move every other session in
/// the program with it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Address {
    /// The address the caller named, consulting nothing.
    Explicit(String),
    /// `VAULT_ADDR`.
    Env,
    /// The `_vault._tcp` SRV record, under each search domain `/etc/resolv.conf`
    /// names.
    Srv,
    /// `VAULT_ADDR`, and the SRV record where it is unset.
    EnvThenSrv,
}

impl Address {
    /// The address this names.
    ///
    /// `srv_cache` names a file a discovered address is kept in for the SRV
    /// record's TTL. Without one every resolution queries — a caller that has
    /// no directory of its own to spare pays a DNS lookup rather than writing
    /// into somebody else's.
    pub async fn resolve(&self, srv_cache: Option<&Path>) -> Result<String> {
        match self {
            Self::Explicit(address) => Ok(address.clone()),
            Self::Env => vault_addr_env()
                .ok_or_else(|| Error::NoAddress("VAULT_ADDR names no address".to_string())),
            Self::Srv => discover(srv_cache).await,
            Self::EnvThenSrv => match vault_addr_env() {
                Some(address) => Ok(address),
                None => {
                    tracing::info!("VAULT_ADDR not set, attempting DNS discovery...");
                    discover(srv_cache).await
                }
            },
        }
    }
}

fn vault_addr_env() -> Option<String> {
    // discard-ok: an unset variable is the case the caller asked about
    env::var("VAULT_ADDR").ok().filter(|a| !a.is_empty())
}

/// Discover the Vault server from its SRV record, through the cache where the
/// caller named one.
async fn discover(cache: Option<&Path>) -> Result<String> {
    if let Some(cache) = cache {
        // discard-ok: a cache miss or an expired entry falls through to discovery
        if let Ok(cached) = read_cache(cache) {
            tracing::debug!("Using cached Vault address: {cached}");
            return Ok(cached);
        }
    }

    let search_domains = parse_resolv_conf_search_domains()?;

    tracing::debug!(
        "Searching for Vault SRV records in domains: {:?}",
        search_domains
    );

    let resolver = TokioResolver::builder_tokio()
        .map_err(|e| Error::Discovery {
            doing: "creating the DNS resolver",
            source: Box::new(e),
        })?
        .build()
        .map_err(|e| Error::Discovery {
            doing: "building the DNS resolver",
            source: Box::new(e),
        })?;

    for domain in search_domains {
        let srv_name = format!("_vault._tcp.{domain}");
        tracing::debug!("Querying SRV record: {srv_name}");

        match resolver.srv_lookup(&srv_name).await {
            Ok(lookup) => {
                // Use the first SRV record found
                let srv_record = lookup
                    .answers()
                    .iter()
                    .find_map(|record| match &record.data {
                        RData::SRV(srv) => Some((srv, record.ttl)),
                        _ => None,
                    });
                if let Some((srv, ttl)) = srv_record {
                    let host = srv.target.to_string();
                    let port = srv.port;

                    // Remove trailing dot from DNS name if present
                    let clean_host = host.trim_end_matches('.');
                    let vault_addr = format!("https://{clean_host}:{port}");

                    tracing::info!("Discovered Vault server via DNS: {vault_addr} (TTL: {ttl}s)");

                    if let Some(cache) = cache {
                        if let Err(e) = write_cache(cache, &vault_addr, ttl) {
                            tracing::warn!(
                                "Failed to cache Vault address: {}",
                                crate::error::render_chain(&e)
                            );
                        }
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

    Err(Error::NoAddress(
        "no SRV records found for _vault._tcp in any search domain".to_string(),
    ))
}

/// Parse search domains from /etc/resolv.conf
fn parse_resolv_conf_search_domains() -> Result<OrderSet<String>> {
    let resolv_conf = fs::read_to_string("/etc/resolv.conf").map_err(|e| Error::Discovery {
        doing: "reading /etc/resolv.conf",
        source: Box::new(e),
    })?;

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
        return Err(Error::NoAddress(
            "no search domains found in /etc/resolv.conf".to_string(),
        ));
    }

    tracing::debug!(
        "Parsed search domains from /etc/resolv.conf: {:?}",
        search_domains
    );
    Ok(search_domains)
}

/// The cached address, where one is there and the record it came from has not
/// yet expired.
fn read_cache(cache: &Path) -> Result<String> {
    if !cache.exists() {
        return Err(Error::NoAddress("no cached Vault address".to_string()));
    }

    let cache_content = fs::read_to_string(cache).map_err(|e| Error::Discovery {
        doing: "reading the cached Vault address",
        source: Box::new(e),
    })?;

    let cached: CachedVaultAddr =
        serde_yaml_ng::from_str(&cache_content).map_err(|e| Error::Discovery {
            doing: "parsing the cached Vault address",
            source: Box::new(e),
        })?;

    let now = now_seconds();
    let expires_at = cached.cached_at + cached.ttl_seconds;

    if now >= expires_at {
        let age = now - cached.cached_at;
        tracing::debug!(
            "DNS cache expired (age: {}s, TTL: {}s), will refresh",
            age,
            cached.ttl_seconds
        );
        return Err(Error::NoAddress(
            "cache expired based on DNS TTL".to_string(),
        ));
    }

    tracing::debug!(
        "Using cached Vault address (TTL remaining: {}s)",
        expires_at - now
    );

    Ok(cached.address)
}

/// Keep the discovered address for as long as the record it came from is good
/// for. The parent directory is the caller's to create: this writes where it
/// was told to and nowhere else.
fn write_cache(cache: &Path, vault_addr: &str, ttl_seconds: u32) -> Result<()> {
    let cached = CachedVaultAddr {
        address: vault_addr.to_string(),
        cached_at: now_seconds(),
        ttl_seconds: ttl_seconds as u64,
    };

    let cache_content = serde_yaml_ng::to_string(&cached).map_err(|e| Error::Discovery {
        doing: "serializing the cached Vault address",
        source: Box::new(e),
    })?;

    fs::write(cache, cache_content).map_err(|e| Error::Discovery {
        doing: "writing the cached Vault address",
        source: Box::new(e),
    })?;

    tracing::debug!(
        "Cached Vault address to: {} (TTL: {}s)",
        cache.display(),
        ttl_seconds
    );
    Ok(())
}

fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = landlock_test_confine::scratch_dir("discovery-tests");
        fs::create_dir_all(&dir).expect("scratch");
        dir.join(name)
    }

    #[tokio::test]
    async fn an_explicit_address_consults_nothing() {
        let named = Address::Explicit("https://vault.example.test:8200".to_string());
        assert_eq!(
            named.resolve(None).await.expect("explicit"),
            "https://vault.example.test:8200"
        );
    }

    /// A cached address is served without a DNS query, which is the only thing
    /// distinguishing it from discovery here: a resolver is not reachable from
    /// a test.
    #[tokio::test]
    async fn a_cached_address_is_served_until_its_record_expires() {
        let cache = scratch("live.yaml");
        fs::write(
            &cache,
            serde_yaml_ng::to_string(&CachedVaultAddr {
                address: "https://cached.example.test:8200".to_string(),
                cached_at: now_seconds(),
                ttl_seconds: 600,
            })
            .expect("cache"),
        )
        .expect("write");

        assert_eq!(
            Address::Srv.resolve(Some(&cache)).await.expect("cached"),
            "https://cached.example.test:8200"
        );
    }

    /// An expired entry is not an address. Reporting it would pin a session to
    /// a server the record has since moved off.
    #[test]
    fn an_expired_entry_is_not_an_address() {
        let cache = scratch("stale.yaml");
        fs::write(
            &cache,
            serde_yaml_ng::to_string(&CachedVaultAddr {
                address: "https://moved.example.test:8200".to_string(),
                cached_at: now_seconds() - 600,
                ttl_seconds: 30,
            })
            .expect("cache"),
        )
        .expect("write");

        read_cache(&cache).expect_err("expired");
    }
}
