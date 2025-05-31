use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::dns::RecordType;
use crate::{NetworkError, Result};

/// A DNS record with TTL information
#[derive(Debug, Clone)]
pub struct DnsRecord {
    /// The record value (IP address or other data)
    pub value: String,
    /// When this record expires
    pub expires_at: Instant,
}

/// A DNS cache that stores records with TTL
pub struct DnsCache {
    records: Arc<RwLock<HashMap<(String, RecordType), DnsRecord>>>,
}

impl DnsCache {
    /// Create a new DNS cache
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get a cached record
    pub fn get(&self, name: &str, record_type: RecordType) -> Option<String> {
        let records = self.records.read().ok()?;
        let key = (name.to_string(), record_type);

        if let Some(record) = records.get(&key) {
            if record.expires_at > Instant::now() {
                return Some(record.value.clone());
            }
        }

        None
    }

    /// Add a record to the cache
    pub fn add(&self, name: &str, record_type: RecordType, value: String, ttl: Duration) {
        if let Ok(mut records) = self.records.write() {
            let key = (name.to_string(), record_type);
            let record = DnsRecord {
                value,
                expires_at: Instant::now() + ttl,
            };
            records.insert(key, record);
        }
    }

    /// Remove a record from the cache
    pub fn remove(&self, name: &str, record_type: RecordType) {
        if let Ok(mut records) = self.records.write() {
            let key = (name.to_string(), record_type);
            records.remove(&key);
        }
    }

    /// Clear expired records from the cache
    pub fn clear_expired(&self) {
        if let Ok(mut records) = self.records.write() {
            records.retain(|_, record| record.expires_at > Instant::now());
        }
    }

    /// Get the TTL for a record
    pub fn get_ttl(&self, name: &str, record_type: RecordType) -> Option<Duration> {
        let records = self.records.read().ok()?;
        let key = (name.to_string(), record_type);

        if let Some(record) = records.get(&key) {
            let now = Instant::now();
            if record.expires_at > now {
                return Some(record.expires_at.duration_since(now));
            }
        }

        None
    }

    /// Clear all records from the cache
    pub fn clear(&self) {
        if let Ok(mut records) = self.records.write() {
            records.clear();
        }
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

/// A thread-safe DNS cache that can be shared between threads
pub struct SharedDnsCache {
    cache: Arc<DnsCache>,
}

impl SharedDnsCache {
    /// Create a new shared DNS cache
    pub fn new() -> Self {
        Self {
            cache: Arc::new(DnsCache::new()),
        }
    }

    /// Get a cached record
    pub fn get(&self, name: &str, record_type: RecordType) -> Option<String> {
        self.cache.get(name, record_type)
    }

    /// Add a record to the cache
    pub fn add(&self, name: &str, record_type: RecordType, value: String, ttl: Duration) {
        self.cache.add(name, record_type, value, ttl);
    }

    /// Remove a record from the cache
    pub fn remove(&self, name: &str, record_type: RecordType) {
        self.cache.remove(name, record_type);
    }

    /// Clear expired records from the cache
    pub fn clear_expired(&self) {
        self.cache.clear_expired();
    }

    /// Get the TTL for a record
    pub fn get_ttl(&self, name: &str, record_type: RecordType) -> Option<Duration> {
        self.cache.get_ttl(name, record_type)
    }

    /// Clear all records from the cache
    pub fn clear(&self) {
        self.cache.clear();
    }
}

impl Default for SharedDnsCache {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for SharedDnsCache {
    fn clone(&self) -> Self {
        Self {
            cache: self.cache.clone(),
        }
    }
}
