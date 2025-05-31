use dns_lookup::{getaddrinfo, getnameinfo, AddrInfoHints};
use std::net::IpAddr;
use std::time::Duration;

use crate::{NetworkError, Result};

/// DNS configuration for the system
#[derive(Debug, Clone)]
pub struct DnsConfig {
    pub nameservers: Vec<IpAddr>,
    pub search_domains: Vec<String>,
    pub timeout: Duration,
    pub attempts: u32,
}

/// DNS resolver with configurable settings
#[derive(Debug, Clone)]
pub struct DnsResolver {
    config: DnsConfig,
}

impl DnsConfig {
    /// Get the system DNS configuration
    pub fn get() -> Result<Self> {
        #[cfg(unix)]
        {
            crate::platform::get_dns_config()
        }
        #[cfg(windows)]
        {
            crate::platform::get_dns_config()
        }
    }
}

impl DnsResolver {
    /// Create a new DNS resolver with the given configuration
    pub fn new(config: DnsConfig) -> Self {
        Self { config }
    }

    /// Create a new DNS resolver with system configuration
    pub fn system() -> Result<Self> {
        Ok(Self {
            config: DnsConfig::get()?,
        })
    }

    /// Resolve a hostname to IP addresses
    pub fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>> {
        let hints = AddrInfoHints {
            socktype: 0,
            protocol: 0,
            flags: 0,
            family: 0,
        };

        getaddrinfo(Some(hostname), None, Some(hints))
            .map_err(|e| NetworkError::Dns(e.to_string()))
            .map(|addrs| addrs.into_iter().map(|addr| addr.ip()).collect())
    }

    /// Perform a reverse DNS lookup
    pub fn reverse_lookup(&self, ip: IpAddr) -> Result<String> {
        getnameinfo(&std::net::SocketAddr::new(ip, 0), 0)
            .map_err(|e| NetworkError::Dns(e.to_string()))
    }

    /// Get the current DNS configuration
    pub fn config(&self) -> &DnsConfig {
        &self.config
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            nameservers: Vec::new(),
            search_domains: Vec::new(),
            timeout: Duration::from_secs(5),
            attempts: 3,
        }
    }
}

impl std::fmt::Display for DnsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "DNS Configuration:")?;
        writeln!(f, "  Nameservers:")?;
        for ns in &self.nameservers {
            writeln!(f, "    {}", ns)?;
        }
        writeln!(f, "  Search Domains:")?;
        for domain in &self.search_domains {
            writeln!(f, "    {}", domain)?;
        }
        writeln!(f, "  Timeout: {:?}", self.timeout)?;
        writeln!(f, "  Attempts: {}", self.attempts)
    }
}
