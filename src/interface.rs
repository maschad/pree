use bytesize::ByteSize;
use std::time::Duration;

use crate::types::{IpNetwork, MacAddress};
use crate::NetworkError;

pub type Result<T> = std::result::Result<T, NetworkError>;

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
    pub fn list() -> Result<Vec<Interface>> {
        #[cfg(unix)]
        {
            crate::platform::list_interfaces()
        }
        #[cfg(windows)]
        {
            crate::platform::list_interfaces()
        }
    }

    /// Get a specific interface by name
    pub fn by_name(name: &str) -> Result<Interface> {
        Self::list()?
            .into_iter()
            .find(|iface| iface.name == name)
            .ok_or_else(|| NetworkError::InterfaceNotFound(name.to_string()))
    }

    /// Get the default interface (usually the one with the default route)
    pub fn default() -> Result<Interface> {
        #[cfg(unix)]
        {
            crate::platform::get_default_interface()
        }
        #[cfg(windows)]
        {
            crate::platform::get_default_interface()
        }
    }

    /// Update the interface statistics
    pub fn update_stats(&mut self) -> Result<()> {
        #[cfg(unix)]
        {
            self.stats = crate::platform::get_interface_stats(&self.name)?;
        }
        #[cfg(windows)]
        {
            self.stats = crate::platform::get_interface_stats(&self.name)?;
        }
        Ok(())
    }

    /// Get the current bandwidth usage (bytes per second)
    pub fn bandwidth(&self, previous_stats: &InterfaceStats) -> (u64, u64) {
        let rx_delta = self.stats.rx_bytes.saturating_sub(previous_stats.rx_bytes);
        let tx_delta = self.stats.tx_bytes.saturating_sub(previous_stats.tx_bytes);
        let time_delta = self
            .stats
            .timestamp
            .saturating_sub(previous_stats.timestamp);

        if time_delta.is_zero() {
            return (0, 0);
        }

        let rx_bps = (rx_delta as f64 / time_delta.as_secs_f64()) as u64;
        let tx_bps = (tx_delta as f64 / time_delta.as_secs_f64()) as u64;

        (rx_bps, tx_bps)
    }
}

impl std::fmt::Display for Interface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Interface: {}", self.name)?;
        writeln!(f, "  Index: {}", self.index)?;
        writeln!(
            f,
            "  MAC: {}",
            self.mac_address
                .map_or("None".to_string(), |m| m.to_string())
        )?;
        writeln!(f, "  MTU: {}", self.mtu)?;
        writeln!(f, "  Status: {}", if self.is_up { "UP" } else { "DOWN" })?;
        writeln!(
            f,
            "  Running: {}",
            if self.is_running { "YES" } else { "NO" }
        )?;
        writeln!(f, "  Type: {:?}", self.kind)?;

        if !self.ipv4.is_empty() {
            writeln!(f, "  IPv4:")?;
            for ip in &self.ipv4 {
                writeln!(f, "    {}", ip)?;
            }
        }

        if !self.ipv6.is_empty() {
            writeln!(f, "  IPv6:")?;
            for ip in &self.ipv6 {
                writeln!(f, "    {}", ip)?;
            }
        }

        writeln!(f, "  Statistics:")?;
        writeln!(
            f,
            "    RX: {} bytes, {} packets",
            ByteSize(self.stats.rx_bytes),
            self.stats.rx_packets
        )?;
        writeln!(
            f,
            "    TX: {} bytes, {} packets",
            ByteSize(self.stats.tx_bytes),
            self.stats.tx_packets
        )?;

        Ok(())
    }
}
