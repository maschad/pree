//! Socket enumeration and monitoring
//!
//! This module provides cross-platform access to system socket information,
//! including TCP and UDP connections with process mapping.

use crate::types::Protocol;
use crate::TcpSocket;
use crate::UdpSocket;
use crate::{ProcessInfo, Result, SocketState};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Common trait for socket configuration and enumeration
pub trait SocketConfig: Sized {
    /// List all sockets of this type
    fn list() -> Result<Vec<Self>>;

    /// List sockets belonging to a specific process
    fn list_by_process(pid: u32) -> Result<Vec<Self>>;

    /// Count active sockets
    fn count_active() -> Result<usize> {
        Ok(Self::list()?.into_iter().filter(|s| s.is_active()).count())
    }

    /// Find socket by local address
    fn find_by_local_addr(addr: SocketAddr) -> Result<Option<Self>> {
        Ok(Self::list()?.into_iter().find(|s| s.local_addr() == addr))
    }

    /// Check if this socket is active (established, listening, or bound)
    fn is_active(&self) -> bool;

    /// Get the local address of this socket
    fn local_addr(&self) -> SocketAddr;

    /// Get the remote address of this socket (if connected)
    fn remote_addr(&self) -> Option<SocketAddr>;

    /// Get the socket state
    fn state(&self) -> SocketState;

    /// Get process information for this socket
    fn process_info(&self) -> Option<&ProcessInfo>;
}

/// Generic socket information that applies to both TCP and UDP
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SocketInfo {
    /// Local socket address
    pub local_addr: SocketAddr,
    /// Remote socket address (None for UDP or unconnected sockets)
    pub remote_addr: Option<SocketAddr>,
    /// Socket state
    pub state: SocketState,
    /// Protocol type
    pub protocol: Protocol,
    /// Process that owns this socket
    pub process: Option<ProcessInfo>,
    /// Socket inode (Unix systems only)
    pub inode: Option<u64>,
    /// Receive queue size in bytes
    pub rx_queue: Option<u32>,
    /// Transmit queue size in bytes
    pub tx_queue: Option<u32>,
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
    /// Timestamp
    pub timestamp: Duration,
}

impl SocketInfo {
    /// Create a new SocketInfo
    pub fn new(
        local_addr: SocketAddr,
        remote_addr: Option<SocketAddr>,
        state: SocketState,
        protocol: Protocol,
    ) -> Self {
        Self {
            local_addr,
            remote_addr,
            state,
            protocol,
            process: None,
            inode: None,
            rx_queue: None,
            tx_queue: None,
            rx_bytes: 0,
            tx_bytes: 0,
            rx_packets: 0,
            tx_packets: 0,
            rx_errors: 0,
            tx_errors: 0,
            timestamp: Duration::from_secs(0),
        }
    }

    /// Check if this socket is actively handling data
    pub fn is_active(&self) -> bool {
        self.state.is_active()
    }

    /// Check if this socket is listening for connections
    pub fn is_listening(&self) -> bool {
        self.state == SocketState::Listen
    }

    /// Check if this socket has an established connection
    pub fn is_established(&self) -> bool {
        self.state == SocketState::Established
    }

    /// Get the port number of the local address
    pub fn local_port(&self) -> u16 {
        self.local_addr.port()
    }

    /// Get the port number of the remote address (if connected)
    pub fn remote_port(&self) -> Option<u16> {
        self.remote_addr.map(|addr| addr.port())
    }

    /// Check if this socket belongs to a specific process
    pub fn belongs_to_process(&self, pid: u32) -> bool {
        self.process.as_ref().map(|p| p.pid) == Some(pid)
    }

    /// Get a human-readable description of this socket
    pub fn description(&self) -> String {
        let process_name = self
            .process
            .as_ref()
            .and_then(|p| p.name.as_ref())
            .map(|n| format!(" ({})", n))
            .unwrap_or_default();

        match self.remote_addr {
            Some(remote) => format!(
                "{} {} -> {} {}{}",
                self.protocol, self.local_addr, remote, self.state, process_name
            ),
            None => format!(
                "{} {} {}{}",
                self.protocol, self.local_addr, self.state, process_name
            ),
        }
    }
}

/// Filter for socket queries
#[derive(Debug, Clone, Default)]
pub struct SocketFilter {
    /// Filter by protocol
    pub protocol: Option<Protocol>,
    /// Filter by state
    pub state: Option<SocketState>,
    /// Filter by process ID
    pub process_id: Option<u32>,
    /// Filter by local port
    pub local_port: Option<u16>,
    /// Filter by remote port
    pub remote_port: Option<u16>,
    /// Only show listening sockets
    pub listening_only: bool,
    /// Only show established connections
    pub established_only: bool,
}

impl SocketFilter {
    /// Create a new empty filter
    pub fn new() -> Self {
        Default::default()
    }

    /// Filter by protocol
    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = Some(protocol);
        self
    }

    /// Filter by state
    pub fn state(mut self, state: SocketState) -> Self {
        self.state = Some(state);
        self
    }

    /// Filter by process ID
    pub fn process_id(mut self, pid: u32) -> Self {
        self.process_id = Some(pid);
        self
    }

    /// Filter by local port
    pub fn local_port(mut self, port: u16) -> Self {
        self.local_port = Some(port);
        self
    }

    /// Filter by remote port
    pub fn remote_port(mut self, port: u16) -> Self {
        self.remote_port = Some(port);
        self
    }

    /// Only show listening sockets
    pub fn listening_only(mut self) -> Self {
        self.listening_only = true;
        self
    }

    /// Only show established connections
    pub fn established_only(mut self) -> Self {
        self.established_only = true;
        self
    }

    /// Check if a socket matches this filter
    pub fn matches(&self, socket: &SocketInfo) -> bool {
        if let Some(protocol) = self.protocol {
            if socket.protocol != protocol {
                return false;
            }
        }

        if let Some(state) = &self.state {
            if socket.state != *state {
                return false;
            }
        }

        if let Some(pid) = self.process_id {
            if !socket.belongs_to_process(pid) {
                return false;
            }
        }

        if let Some(port) = self.local_port {
            if socket.local_port() != port {
                return false;
            }
        }

        if let Some(port) = self.remote_port {
            if socket.remote_port() != Some(port) {
                return false;
            }
        }

        if self.listening_only && !socket.is_listening() {
            return false;
        }

        if self.established_only && !socket.is_established() {
            return false;
        }

        true
    }
}

/// Apply a filter to a list of sockets
pub fn filter_sockets(sockets: Vec<SocketInfo>, filter: &SocketFilter) -> Vec<SocketInfo> {
    sockets.into_iter().filter(|s| filter.matches(s)).collect()
}

/// Get all sockets (TCP and UDP) matching the filter
pub fn list_all_sockets(filter: Option<SocketFilter>) -> Result<Vec<SocketInfo>> {
    let mut sockets = Vec::new();

    // Get TCP sockets
    for tcp_socket in TcpSocket::list()? {
        sockets.push(tcp_socket.into());
    }

    // Get UDP sockets
    for udp_socket in UdpSocket::list()? {
        sockets.push(udp_socket.into());
    }

    // Apply filter if provided
    if let Some(filter) = filter {
        sockets = filter_sockets(sockets, &filter);
    }

    Ok(sockets)
}

/// Count total active sockets (TCP + UDP)
pub fn count_total_active() -> Result<usize> {
    let tcp_count = TcpSocket::count_active()?;
    let udp_count = UdpSocket::count_active()?;
    Ok(tcp_count + udp_count)
}

/// State of a TCP socket
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TcpState {
    Established,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Close,
    CloseWait,
    LastAck,
    Listen,
    Closing,
    NewSynRecv,
    Other(u8),
}

impl Default for TcpState {
    fn default() -> Self {
        TcpState::Established
    }
}

impl From<TcpState> for SocketState {
    fn from(state: TcpState) -> Self {
        match state {
            TcpState::Established => SocketState::Established,
            TcpState::Listen => SocketState::Listen,
            _ => SocketState::Unknown("Unknown TCP state".to_string()),
        }
    }
}

/// Information about a network socket
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Socket {
    pub protocol: Protocol,
    pub local_addr: SocketAddr,
    pub remote_addr: Option<SocketAddr>,
    pub state: Option<SocketState>,
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
    pub user_id: Option<u32>,
    pub inode: Option<u64>,
}

impl Socket {
    /// Get all open sockets
    pub fn list() -> Result<Vec<Socket>> {
        #[cfg(unix)]
        {
            crate::socket::platform::get_sockets_info()
                .map_err(|e| crate::error::Error::from(e))?
                .into_iter()
                .map(|info| {
                    Ok(Socket {
                        protocol: info.protocol,
                        local_addr: info.local_addr,
                        remote_addr: Some(info.remote_addr),
                        state: Some(info.state),
                        process_id: info.process_id,
                        process_name: info.process_name,
                        user_id: None,
                        inode: None,
                    })
                })
                .collect()
        }
        #[cfg(windows)]
        {
            crate::socket::platform::get_sockets_info()
                .map_err(|e| crate::error::Error::from(e))?
                .into_iter()
                .map(|info| {
                    Ok(Socket {
                        protocol: info.protocol,
                        local_addr: info.local_addr,
                        remote_addr: Some(info.remote_addr),
                        state: Some(info.state),
                        process_id: info.process_id,
                        process_name: info.process_name,
                        user_id: None,
                        inode: None,
                    })
                })
                .collect()
        }
    }

    /// Get sockets for a specific process
    pub fn for_process(pid: u32) -> Result<Vec<Socket>> {
        Ok(Self::list()?
            .into_iter()
            .filter(|socket| socket.process_id == Some(pid))
            .collect())
    }

    /// Get sockets listening on a specific port
    pub fn listening_on(port: u16) -> Result<Vec<Socket>> {
        Ok(Self::list()?
            .into_iter()
            .filter(|socket| socket.local_addr.port() == port)
            .collect())
    }

    /// Get sockets connected to a specific address
    pub fn connected_to(addr: IpAddr) -> Result<Vec<Socket>> {
        Ok(Self::list()?
            .into_iter()
            .filter(|socket| {
                socket
                    .remote_addr
                    .map(|remote| remote.ip() == addr)
                    .unwrap_or(false)
            })
            .collect())
    }
}

impl std::fmt::Display for Socket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self.protocol {
                Protocol::Tcp => "tcp",
                Protocol::Udp => "udp",
                Protocol::Raw => "raw",
                Protocol::Icmp => "icmp",
                Protocol::Other(p) => return write!(f, "proto({})", p),
            }
        )?;

        write!(f, " {}:{}", self.local_addr.ip(), self.local_addr.port())?;

        if let Some(remote) = self.remote_addr {
            write!(f, " {}:{}", remote.ip(), remote.port())?;
        }

        if let Some(state) = &self.state {
            write!(
                f,
                " {}",
                match state {
                    SocketState::Established => "ESTABLISHED",
                    SocketState::Listen => "LISTEN",
                    SocketState::Connecting => "CONNECTING",
                    SocketState::Closing => "CLOSING",
                    SocketState::Closed => "CLOSED",
                    SocketState::Bound => "BOUND",
                    SocketState::Unknown(_) => "UNKNOWN",
                }
            )?;
        }

        if let Some(pid) = self.process_id {
            write!(f, " pid={}", pid)?;
            if let Some(name) = &self.process_name {
                write!(f, " ({})", name)?;
            }
        }

        Ok(())
    }
}

impl std::fmt::Display for SocketInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "{} {} -> {} {}",
            self.protocol,
            self.local_addr,
            self.remote_addr.unwrap_or(self.local_addr),
            self.state
        )?;
        writeln!(
            f,
            "  RX: {} bytes, {} packets, {} errors",
            self.rx_bytes, self.rx_packets, self.rx_errors
        )?;
        writeln!(
            f,
            "  TX: {} bytes, {} packets, {} errors",
            self.tx_bytes, self.tx_packets, self.tx_errors
        )
    }
}

impl From<crate::socket::tcp::TcpSocket> for SocketInfo {
    fn from(socket: crate::socket::tcp::TcpSocket) -> Self {
        Self::new(
            socket.local_addr,
            socket.remote_addr,
            socket.state(),
            Protocol::Tcp,
        )
    }
}

impl From<crate::socket::udp::UdpSocket> for SocketInfo {
    fn from(socket: crate::socket::udp::UdpSocket) -> Self {
        Self::new(
            socket.local_addr,
            socket.remote_addr,
            socket.state,
            Protocol::Udp,
        )
    }
}

// Re-export platform-specific functions
pub use crate::socket::platform::{
    get_available_ports, get_ephemeral_port_range, get_system_socket_limit, is_port_available,
};
