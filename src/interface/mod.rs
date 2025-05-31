mod monitor;
mod nat;

pub use monitor::{InterfaceEvent, InterfaceMonitor};
pub use nat::{get_local_ip, get_public_ip, NatDetectionMethod, NatDetector};

use crate::types::{IpNetwork, MacAddress};
use std::time::Duration;

/// Represents the type of network interface
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceKind {
    Loopback,
    Ethernet,
    Wireless,
    Virtual,
    Tunnel,
    Other(String),
}

/// Statistics for a network interface
#[derive(Debug, Clone, Default)]
pub struct InterfaceStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub rx_fifo_errors: u64,
    pub tx_fifo_errors: u64,
    pub rx_frame_errors: u64,
    pub tx_collisions: u64,
    pub rx_compressed: u64,
    pub tx_compressed: u64,
    pub multicast: u64,
    pub timestamp: Duration,
}

/// Represents a network interface
#[derive(Debug, Clone)]
pub struct Interface {
    pub name: String,
    pub index: u32,
    pub mac_address: Option<MacAddress>,
    pub mtu: u32,
    pub is_up: bool,
    pub is_running: bool,
    pub kind: InterfaceKind,
    pub ipv4: Vec<IpNetwork>,
    pub ipv6: Vec<IpNetwork>,
    pub stats: InterfaceStats,
}

impl Interface {
    /// Get all available network interfaces
    ///
    /// # Errors
    /// Returns an error if interface listing fails
    pub fn list() -> crate::Result<Vec<Self>> {
        #[cfg(unix)]
        {
            crate::platform::list_interfaces()
        }
        #[cfg(windows)]
        {
            crate::platform::list_interfaces()
        }
    }

    /// Get interface type
    #[must_use]
    pub const fn interface_type(&self) -> &InterfaceKind {
        &self.kind
    }

    /// Check if interface is up
    #[must_use]
    pub const fn is_up(&self) -> bool {
        self.is_up
    }

    /// Get all IP addresses
    #[must_use]
    pub fn ip_addresses(&self) -> Vec<String> {
        let mut ips = Vec::new();
        for ip in &self.ipv4 {
            ips.push(ip.to_string());
        }
        for ip in &self.ipv6 {
            ips.push(ip.to_string());
        }
        ips
    }

    /// Check if interface is a loopback interface
    #[must_use]
    pub fn is_loopback(&self) -> bool {
        self.kind == InterfaceKind::Loopback
    }
}
