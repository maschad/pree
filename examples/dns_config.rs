use pree::dns::{DnsCache, DnsResolver, RecordType};
use std::time::Duration;

fn main() -> pree::Result<()> {
    // Create a DNS resolver with caching
    let resolver = DnsResolver::builder()
        .cache(DnsCache::new())
        .timeout(Duration::from_secs(5))
        .build()?;

    // Get system DNS settings
    let system_dns = DnsResolver::system()?;
    println!("System DNS Servers:");
    for server in system_dns.nameservers() {
        println!("  {server}");
    }
    println!("Search Domains: {}", system_dns.search_domains().join(", "));

    // Perform some DNS lookups
    let domains = ["example.com", "google.com", "github.com"];
    for domain in domains {
        println!("\nResolving {domain}:");

        // A records
        if let Ok(records) = resolver.lookup(domain, RecordType::A) {
            println!("  A Records:");
            for record in records {
                println!("    {record}");
            }
        }

        // AAAA records
        if let Ok(records) = resolver.lookup(domain, RecordType::AAAA) {
            println!("  AAAA Records:");
            for record in records {
                println!("    {record}");
            }
        }

        // MX records
        if let Ok(records) = resolver.lookup(domain, RecordType::MX) {
            println!("  MX Records:");
            for record in records {
                println!("    {record}");
            }
        }

        // Check cache TTL
        if let Some(ttl) = resolver.get_cache_ttl(domain, RecordType::A)? {
            println!("  Cache TTL: {} seconds", ttl.as_secs());
        }
    }

    // Force refresh cache for a domain
    println!("\nRefreshing cache for example.com...");
    resolver.refresh_cache("example.com", RecordType::A)?;

    Ok(())
}
