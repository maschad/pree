use std::time::Duration;

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::Resolver;

use super::cache::{DnsCache, SharedDnsCache};
use super::{DnsConfig, RecordType};
use crate::{NetworkError, Result};

/// DNS resolver configuration
#[derive(Debug, Clone)]
pub struct DnsResolver {
    config: DnsConfig,
    cache: Option<SharedDnsCache>,
    timeout: Duration,
    attempts: u32,
}

impl Default for DnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsResolver {
    /// Create a new DNS resolver with default settings
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: DnsConfig::default(),
            cache: None,
            timeout: Duration::from_secs(5),
            attempts: 3,
        }
    }

    /// Create a builder for configuring the resolver
    #[must_use]
    pub fn builder() -> DnsResolverBuilder {
        DnsResolverBuilder::new()
    }

    /// Create a resolver using system DNS settings
    ///
    /// # Errors
    /// Returns an error if system DNS configuration cannot be read
    pub fn system() -> Result<Self> {
        let config = DnsConfig::get()?;
        Ok(Self {
            config,
            cache: None,
            timeout: Duration::from_secs(5),
            attempts: 3,
        })
    }

    /// Get the nameservers configured in the resolver
    #[must_use]
    pub fn nameservers(&self) -> &[std::net::IpAddr] {
        &self.config.nameservers
    }

    /// Get the search domains configured in the resolver
    #[must_use]
    pub fn search_domains(&self) -> &[String] {
        &self.config.search_domains
    }

    /// Lookup DNS records
    ///
    /// # Errors
    /// Returns an error if the DNS lookup fails
    pub fn lookup(&self, name: &str, record_type: RecordType) -> Result<Vec<String>> {
        // Check cache first
        if let Some(cache) = &self.cache {
            if let Some(value) = cache.get(name, record_type) {
                return Ok(vec![value]);
            }
        }

        // Perform DNS lookup
        let records = Self::do_lookup(name, record_type)?;

        // Cache the results
        if let Some(cache) = &self.cache {
            for record in &records {
                // Use a default TTL of 5 minutes if not provided by the DNS server
                cache.add(name, record_type, record.clone(), Duration::from_secs(300));
            }
        }

        Ok(records)
    }

    /// Get the TTL for a cached record
    ///
    /// # Errors
    /// This function currently never returns an error but is marked as `Result` for API consistency
    pub fn get_cache_ttl(&self, name: &str, record_type: RecordType) -> Result<Option<Duration>> {
        Ok(self.cache.as_ref().and_then(|cache| cache.get_ttl(name, record_type)))
    }

    /// Force refresh the cache for a record
    ///
    /// # Errors
    /// Returns an error if the DNS lookup fails during refresh
    pub fn refresh_cache(&self, name: &str, record_type: RecordType) -> Result<()> {
        if let Some(cache) = &self.cache {
            cache.remove(name, record_type);
            let _ = self.lookup(name, record_type)?;
        }
        Ok(())
    }

    /// Perform the actual DNS lookup
    fn do_lookup(name: &str, record_type: RecordType) -> Result<Vec<String>> {
        // Use system resolver
        let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())
            .map_err(|e| NetworkError::Dns(format!("Failed to create resolver: {e}")))?;

        match record_type {
            RecordType::A => {
                let response = resolver
                    .ipv4_lookup(name)
                    .map_err(|e| NetworkError::Dns(format!("A lookup failed: {e}")))?;
                Ok(response.iter().map(std::string::ToString::to_string).collect())
            }
            RecordType::AAAA => {
                let response = resolver
                    .ipv6_lookup(name)
                    .map_err(|e| NetworkError::Dns(format!("AAAA lookup failed: {e}")))?;
                Ok(response.iter().map(std::string::ToString::to_string).collect())
            }
            RecordType::MX => {
                let response = resolver
                    .mx_lookup(name)
                    .map_err(|e| NetworkError::Dns(format!("MX lookup failed: {e}")))?;
                Ok(response
                    .iter()
                    .map(|mx| format!("{} {}", mx.preference(), mx.exchange()))
                    .collect())
            }
            RecordType::TXT => {
                let response = resolver
                    .txt_lookup(name)
                    .map_err(|e| NetworkError::Dns(format!("TXT lookup failed: {e}")))?;
                Ok(response.iter().map(std::string::ToString::to_string).collect())
            }
            RecordType::CNAME
            | RecordType::NS
            | RecordType::PTR
            | RecordType::SRV
            | RecordType::SOA => Err(NetworkError::NotImplemented(format!(
                "DNS record type {record_type} not yet supported"
            ))
            .into()),
        }
    }
}

/// Builder for configuring a DNS resolver
pub struct DnsResolverBuilder {
    resolver: DnsResolver,
}

impl DnsResolverBuilder {
    /// Create a new builder
    #[must_use]
    pub fn new() -> Self {
        Self {
            resolver: DnsResolver::new(),
        }
    }

    /// Enable caching
    #[must_use]
    pub fn cache(mut self, _cache: DnsCache) -> Self {
        // Create a new SharedDnsCache for the resolver
        self.resolver.cache = Some(SharedDnsCache::new());
        self
    }

    /// Set the timeout for DNS lookups
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.resolver.timeout = timeout;
        self
    }

    /// Set the number of lookup attempts
    #[must_use]
    pub const fn attempts(mut self, attempts: u32) -> Self {
        self.resolver.attempts = attempts;
        self
    }

    /// Build the resolver
    ///
    /// # Errors
    /// This function currently never returns an error but is marked as `Result` for API consistency
    pub fn build(self) -> Result<DnsResolver> {
        Ok(self.resolver)
    }
}

impl Default for DnsResolverBuilder {
    fn default() -> Self {
        Self::new()
    }
}
