#![allow(clippy::uninlined_format_args)]
#![allow(clippy::cast_precision_loss)]

use std::net::IpAddr;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

#[cfg(feature = "serde-support")]
use serde::{Deserialize, Serialize};

/// Represents the state of a network socket
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub enum SocketState {
    /// Socket is listening for connections (TCP only)
    Listen,
    /// Socket has an established connection
    Established,
    /// Socket is in the process of connecting
    Connecting,
    /// Socket is closing
    Closing,
    /// Socket is closed
    Closed,
    /// Socket is bound but not connected (UDP)
    Bound,
    /// Unknown or platform-specific state
    Unknown(String),
}

impl SocketState {
    /// Returns true if the socket is actively handling data
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Established | Self::Listen | Self::Bound)
    }

    /// Returns true if the socket is in a transitional state
    #[must_use]
    pub const fn is_transitional(&self) -> bool {
        matches!(self, Self::Connecting | Self::Closing)
    }
}

impl std::fmt::Display for SocketState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Listen => write!(f, "LISTEN"),
            Self::Established => write!(f, "ESTABLISHED"),
            Self::Connecting => write!(f, "CONNECTING"),
            Self::Closing => write!(f, "CLOSING"),
            Self::Closed => write!(f, "CLOSED"),
            Self::Bound => write!(f, "BOUND"),
            Self::Unknown(state) => write!(f, "{state}"),
        }
    }
}

/// Information about a process that owns a socket
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct ProcessInfo {
    /// Process ID
    pub pid: u32,
    /// Process name (if available)
    pub name: Option<String>,
    /// Command line arguments (if available and accessible)
    pub cmdline: Option<String>,
    /// User ID that owns the process (Unix only)
    pub uid: Option<u32>,
    /// Start time of the process
    pub start_time: Option<SystemTime>,
    /// Memory usage of the process
    pub memory_usage: Option<u64>,
    /// CPU usage of the process
    pub cpu_usage: Option<u64>,
    /// User that owns the process
    pub user: Option<String>,
}

impl ProcessInfo {
    /// Create a new instance with just a PID
    #[must_use]
    pub const fn new(pid: u32) -> Self {
        Self {
            pid,
            name: None,
            cmdline: None,
            uid: None,
            start_time: None,
            memory_usage: None,
            cpu_usage: None,
            user: None,
        }
    }

    /// Create a instance with PID and name
    #[must_use]
    pub const fn with_name(pid: u32, name: String) -> Self {
        Self {
            pid,
            name: Some(name),
            cmdline: None,
            uid: None,
            start_time: None,
            memory_usage: None,
            cpu_usage: None,
            user: None,
        }
    }
}

/// Protocol type for network connections
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub enum Protocol {
    /// Transmission Control Protocol
    Tcp,
    /// User Datagram Protocol
    Udp,
    /// Internet Control Message Protocol
    Icmp,
    /// Raw socket
    Raw,
    /// Other protocol
    Other(u8),
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
            Self::Icmp => write!(f, "ICMP"),
            Self::Raw => write!(f, "RAW"),
            Self::Other(n) => write!(f, "PROTO_{n}"),
        }
    }
}

/// Network interface statistics snapshot
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct InterfaceStats {
    /// Interface name
    pub interface: String,
    /// Timestamp when stats were collected
    pub timestamp: SystemTime,
    /// Bytes received
    pub rx_bytes: u64,
    /// Bytes transmitted
    pub tx_bytes: u64,
    /// Packets received
    pub rx_packets: u64,
    /// Packets transmitted
    pub tx_packets: u64,
    /// Receive errors
    pub rx_errors: u64,
    /// Transmit errors
    pub tx_errors: u64,
    /// Dropped packets (receive)
    pub rx_dropped: u64,
    /// Dropped packets (transmit)
    pub tx_dropped: u64,
}

impl InterfaceStats {
    /// Calculate the difference between two stats snapshots
    #[allow(dead_code)]
    pub fn diff(&self, other: &Self) -> Option<InterfaceStatsDiff> {
        if self.interface != other.interface {
            return None;
        }

        let duration = other.timestamp.duration_since(self.timestamp).ok()?;

        Some(InterfaceStatsDiff {
            interface: self.interface.clone(),
            duration,
            rx_bytes: other.rx_bytes.saturating_sub(self.rx_bytes),
            tx_bytes: other.tx_bytes.saturating_sub(self.tx_bytes),
            rx_packets: other.rx_packets.saturating_sub(self.rx_packets),
            tx_packets: other.tx_packets.saturating_sub(self.tx_packets),
            rx_errors: other.rx_errors.saturating_sub(self.rx_errors),
            tx_errors: other.tx_errors.saturating_sub(self.tx_errors),
            rx_dropped: other.rx_dropped.saturating_sub(self.rx_dropped),
            tx_dropped: other.tx_dropped.saturating_sub(self.tx_dropped),
        })
    }
}

/// Difference between two interface statistics snapshots
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct InterfaceStatsDiff {
    /// Interface name
    pub interface: String,
    /// Time duration between snapshots
    pub duration: Duration,
    /// Bytes received in period
    pub rx_bytes: u64,
    /// Bytes transmitted in period
    pub tx_bytes: u64,
    /// Packets received in period
    pub rx_packets: u64,
    /// Packets transmitted in period
    pub tx_packets: u64,
    /// Receive errors in period
    pub rx_errors: u64,
    /// Transmit errors in period
    pub tx_errors: u64,
    /// Dropped packets (receive) in period
    pub rx_dropped: u64,
    /// Dropped packets (transmit) in period
    pub tx_dropped: u64,
}

impl InterfaceStatsDiff {
    /// Calculate receive bandwidth in bytes per second
    #[allow(dead_code)]
    pub fn rx_bandwidth_bps(&self) -> f64 {
        if self.duration.as_secs_f64() > 0.0 {
            self.rx_bytes as f64 / self.duration.as_secs_f64()
        } else {
            0.0
        }
    }

    /// Calculate transmit bandwidth in bytes per second
    #[allow(dead_code)]
    pub fn tx_bandwidth_bps(&self) -> f64 {
        if self.duration.as_secs_f64() > 0.0 {
            self.tx_bytes as f64 / self.duration.as_secs_f64()
        } else {
            0.0
        }
    }

    /// Calculate total bandwidth in bytes per second
    #[allow(dead_code)]
    pub fn total_bandwidth_bps(&self) -> f64 {
        self.rx_bandwidth_bps() + self.tx_bandwidth_bps()
    }

    /// Calculate receive packet rate per second
    #[allow(dead_code)]
    pub fn rx_packet_rate(&self) -> f64 {
        if self.duration.as_secs_f64() > 0.0 {
            self.rx_packets as f64 / self.duration.as_secs_f64()
        } else {
            0.0
        }
    }

    /// Calculate transmit packet rate per second
    #[allow(dead_code)]
    pub fn tx_packet_rate(&self) -> f64 {
        if self.duration.as_secs_f64() > 0.0 {
            self.tx_packets as f64 / self.duration.as_secs_f64()
        } else {
            0.0
        }
    }
}

/// A network route entry
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct RouteEntry {
    /// Destination network
    pub destination: IpAddr,
    /// Network mask
    pub netmask: IpAddr,
    /// Gateway IP address
    pub gateway: Option<IpAddr>,
    /// Network interface name
    pub interface: String,
    /// Route metric/priority
    pub metric: Option<u32>,
    /// Whether this is the default route
    pub is_default: bool,
}

/// DNS server configuration
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct DnsServer {
    /// DNS server IP address
    pub address: IpAddr,
    /// Port (usually 53)
    pub port: u16,
    /// Whether this is the primary DNS server
    pub is_primary: bool,
}

impl Default for DnsServer {
    fn default() -> Self {
        Self {
            address: "8.8.8.8".parse().unwrap(),
            port: 53,
            is_primary: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpNetwork {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl IpNetwork {
    pub const fn new(addr: IpAddr, prefix: u8) -> Self {
        Self { addr, prefix }
    }

    pub const fn is_default(&self) -> bool {
        self.prefix == 0
    }
}

impl std::fmt::Display for IpNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl FromStr for IpNetwork {
    type Err = crate::error::NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() != 2 {
            return Err(crate::error::NetworkError::InvalidIpAddress(s.to_string()));
        }

        let addr = parts[0]
            .parse::<IpAddr>()
            .map_err(|_| crate::error::NetworkError::InvalidIpAddress(parts[0].to_string()))?;
        let prefix = parts[1]
            .parse::<u8>()
            .map_err(|_| crate::error::NetworkError::InvalidIpAddress(s.to_string()))?;

        Ok(Self { addr, prefix })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    pub const fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

impl std::fmt::Display for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl FromStr for MacAddress {
    type Err = crate::error::NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return Err(crate::error::NetworkError::InvalidMacAddress(s.to_string()));
        }

        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            bytes[i] = u8::from_str_radix(part, 16)
                .map_err(|_| crate::error::NetworkError::InvalidMacAddress(s.to_string()))?;
        }

        Ok(Self(bytes))
    }
}
