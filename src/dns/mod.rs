pub mod cache;
pub mod resolver;

// Re-export main types
pub use cache::{DnsCache, SharedDnsCache};
pub use resolver::{DnsResolver, DnsResolverBuilder};

use std::net::IpAddr;
use std::time::Duration;

use crate::Result;

/// DNS record types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    /// IPv4 address record
    A,
    /// IPv6 address record
    AAAA,
    /// Mail exchange record
    MX,
    /// Canonical name record
    CNAME,
    /// Text record
    TXT,
    /// Name server record
    NS,
    /// Pointer record (reverse DNS)
    PTR,
    /// Service locator
    SRV,
    /// Start of authority record
    SOA,
}

impl std::fmt::Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::A => write!(f, "A"),
            Self::AAAA => write!(f, "AAAA"),
            Self::MX => write!(f, "MX"),
            Self::CNAME => write!(f, "CNAME"),
            Self::TXT => write!(f, "TXT"),
            Self::NS => write!(f, "NS"),
            Self::PTR => write!(f, "PTR"),
            Self::SRV => write!(f, "SRV"),
            Self::SOA => write!(f, "SOA"),
        }
    }
}

/// DNS configuration for the system
#[derive(Debug, Clone)]
pub struct DnsConfig {
    pub nameservers: Vec<IpAddr>,
    pub search_domains: Vec<String>,
    pub timeout: Duration,
    pub attempts: u32,
}

impl DnsConfig {
    /// Get the system DNS configuration
    ///
    /// # Errors
    /// Returns an error if system DNS configuration cannot be read
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
            writeln!(f, "    {ns}")?;
        }
        writeln!(f, "  Search Domains:")?;
        for domain in &self.search_domains {
            writeln!(f, "    {domain}")?;
        }
        writeln!(f, "  Timeout: {:?}", self.timeout)?;
        writeln!(f, "  Attempts: {}", self.attempts)
    }
}
