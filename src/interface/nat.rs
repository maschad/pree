use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use crate::interface::Interface;
use crate::{Error, Result};

/// NAT detection methods
#[derive(Debug, Clone, Copy)]
pub enum NatDetectionMethod {
    /// Use STUN server to detect NAT
    Stun,
    /// Use socket introspection to detect NAT
    SocketIntrospection,
    /// Use both methods
    Both,
}

/// NAT detection configuration
#[derive(Debug, Clone)]
pub struct NatDetector {
    method: NatDetectionMethod,
    stun_servers: Vec<String>,
    timeout: Duration,
}

impl Default for NatDetector {
    fn default() -> Self {
        Self {
            method: NatDetectionMethod::Both,
            stun_servers: vec![
                "stun.l.google.com:19302".to_string(),
                "stun1.l.google.com:19302".to_string(),
                "stun2.l.google.com:19302".to_string(),
            ],
            timeout: Duration::from_secs(5),
        }
    }
}

impl NatDetector {
    /// Create a new NAT detector with default settings
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the detection method
    #[must_use]
    pub const fn method(mut self, method: NatDetectionMethod) -> Self {
        self.method = method;
        self
    }

    /// Set custom STUN servers
    #[must_use]
    pub fn stun_servers(mut self, servers: Vec<String>) -> Self {
        self.stun_servers = servers;
        self
    }

    /// Set the timeout for detection attempts
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Detect NAT using STUN servers
    #[allow(clippy::unused_self)]
    fn detect_via_stun(&self) -> Result<bool> {
        // TODO: Implement STUN-based NAT detection
        // This would require a STUN client implementation
        Err(Error::unsupported_platform("STUN detection"))
    }

    /// Detect NAT using socket introspection
    #[allow(clippy::unused_self)]
    fn detect_via_socket(&self) -> Result<bool> {
        let interfaces = Interface::list()?;
        let mut has_private_ip = false;
        let mut has_public_ip = false;

        for interface in interfaces {
            if !interface.is_up() || interface.is_loopback() {
                continue;
            }

            for ip_str in interface.ip_addresses() {
                if let Ok(ip) = IpAddr::from_str(&ip_str) {
                    if is_private_ip(ip) {
                        has_private_ip = true;
                    } else if is_public_ip(ip) {
                        has_public_ip = true;
                    }
                }
            }
        }

        // If we have both private and public IPs, we're likely behind NAT
        Ok(has_private_ip && has_public_ip)
    }

    /// Check if the system is behind NAT
    ///
    /// # Errors
    /// Returns an error if interface listing fails or if NAT detection fails
    pub fn is_behind_nat(&self) -> Result<bool> {
        match self.method {
            NatDetectionMethod::Stun => self.detect_via_stun(),
            NatDetectionMethod::SocketIntrospection => self.detect_via_socket(),
            NatDetectionMethod::Both => {
                // Try STUN first, fall back to socket introspection
                self.detect_via_stun()
                    .map_or_else(|_| self.detect_via_socket(), Ok)
            }
        }
    }
}

/// Check if an IP address is private
const fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            // RFC 1918 private ranges
            ip.octets()[0] == 10
                || (ip.octets()[0] == 172 && ip.octets()[1] >= 16 && ip.octets()[1] <= 31)
                || (ip.octets()[0] == 192 && ip.octets()[1] == 168)
                // RFC 3927 link-local
                || (ip.octets()[0] == 169 && ip.octets()[1] == 254)
        }
        IpAddr::V6(ip) => {
            // RFC 4193 unique local
            ip.segments()[0] & 0xfe00 == 0xfc00
                // RFC 4291 link-local
                || ip.segments()[0] & 0xffc0 == 0xfe80
        }
    }
}

/// Check if an IP address is public
const fn is_public_ip(ip: IpAddr) -> bool {
    !is_private_ip(ip) && !ip.is_loopback() && !ip.is_unspecified()
}

/// Get the public IP address of the system
///
/// # Errors
/// Returns an error if interface listing fails
pub fn get_public_ip() -> Result<Option<IpAddr>> {
    let interfaces = Interface::list()?;
    for interface in interfaces {
        if !interface.is_up() || interface.is_loopback() {
            continue;
        }

        for ip_str in interface.ip_addresses() {
            if let Ok(ip) = IpAddr::from_str(&ip_str) {
                if is_public_ip(ip) {
                    return Ok(Some(ip));
                }
            }
        }
    }

    Ok(None)
}

/// Get the local IP address of the system
///
/// # Errors
/// Returns an error if interface listing fails
pub fn get_local_ip() -> Result<Option<IpAddr>> {
    let interfaces = Interface::list()?;
    for interface in interfaces {
        if !interface.is_up() || interface.is_loopback() {
            continue;
        }

        for ip_str in interface.ip_addresses() {
            if let Ok(ip) = IpAddr::from_str(&ip_str) {
                if is_private_ip(ip) {
                    return Ok(Some(ip));
                }
            }
        }
    }

    Ok(None)
}
