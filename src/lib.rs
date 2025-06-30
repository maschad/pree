#![cfg_attr(docsrs, feature(doc_cfg))]

//! # Pree
//!
//! A cross-platform network diagnostics and monitoring library for Rust applications.
//!
//! This crate provides standardized access to network information across Linux, macOS, and Windows:
//! - Socket enumeration and monitoring (TCP/UDP)
//! - Real-time traffic statistics and bandwidth monitoring
//! - DNS configuration access
//! - Routing table information
//! - Network interface discovery and stats
//!
//! ## Quick Start
//!
//! ```rust
//! use pree::{TcpSocket, UdpSocket, SocketConfig};
//!
//! // List all active TCP connections
//! let tcp_sockets = TcpSocket::list()?;
//! println!("Active TCP connections: {}", tcp_sockets.len());
//!
//! // Count UDP sockets
//! let udp_count = UdpSocket::count_active()?;
//! println!("Active UDP sockets: {}", udp_count);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Features
//!
//! - `async` - Enable async/await support for streaming monitoring
//! - `serde` - Enable serialization support for all data structures

mod error;
mod platform;
mod types;

pub mod interface;
pub mod routing;
pub mod socket;

// Re-export core types and traits
pub use error::{Error, Result};
pub use types::{ProcessInfo, Protocol, SocketState};

// Interface monitoring (extends network-interface functionality)
use crate::error::NetworkError;
pub use interface::{Interface, InterfaceEvent, InterfaceMonitor, InterfaceStats};

// Socket enumeration
pub use socket::monitor::SocketMonitor;
pub use socket::platform::SocketInfo;
pub use socket::socket::SocketConfig;
pub use socket::tcp::TcpSocket;
pub use socket::udp::UdpSocket;

// Routing and DNS
pub use types::RouteEntry;

// Utility functions
pub use socket::platform::{get_available_ports, get_system_socket_limit};

// Optional async monitoring (behind feature flag)
#[cfg(feature = "async")]
pub use monitor::AsyncTrafficStream;

/// Result type for network operations
pub type NetworkResult<T> = std::result::Result<T, NetworkError>;

/// Platform-specific implementation details
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

/// Platform-specific types
#[cfg(unix)]
pub use unix::*;
#[cfg(windows)]
pub use windows::*;
