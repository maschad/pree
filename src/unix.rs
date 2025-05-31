use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nix::net::if_::InterfaceFlags;

use crate::interface::{Interface, InterfaceKind, InterfaceStats};
use crate::types::{IpNetwork, MacAddress};
use crate::NetworkError;

pub type Result<T> = std::result::Result<T, NetworkError>;

/// List all available network interfaces
pub fn list_interfaces() -> Result<Vec<Interface>> {
    let mut interfaces = Vec::new();

    // Read from /sys/class/net
    let net_dir = Path::new("/sys/class/net");
    for entry in fs::read_dir(net_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();

        if let Ok(interface) = get_interface_info(&name) {
            interfaces.push(interface);
        }
    }

    Ok(interfaces)
}

/// Get information about a specific interface
fn get_interface_info(name: &str) -> Result<Interface> {
    let base_path = Path::new("/sys/class/net").join(name);

    // Read interface flags
    let flags = fs::read_to_string(base_path.join("flags"))?;
    let flags = u32::from_str_radix(flags.trim(), 16)?;
    let flags = InterfaceFlags::from_bits_truncate(flags as i32);

    // Read MTU
    let mtu = fs::read_to_string(base_path.join("mtu"))?.trim().parse()?;

    // Read MAC address
    let mac = fs::read_to_string(base_path.join("address"))?;
    let mac = mac.trim();
    let mac_address = if mac != "00:00:00:00:00:00" {
        let bytes: Vec<u8> = mac
            .split(':')
            .map(|b| u8::from_str_radix(b, 16).unwrap_or(0))
            .collect();
        if bytes.len() == 6 {
            Some(MacAddress::new([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
            ]))
        } else {
            None
        }
    } else {
        None
    };

    // Determine interface type
    let kind = if flags.contains(InterfaceFlags::IFF_LOOPBACK) {
        InterfaceKind::Loopback
    } else if name.starts_with("wlan") || name.starts_with("wifi") {
        InterfaceKind::Wireless
    } else if name.starts_with("eth") || name.starts_with("en") {
        InterfaceKind::Ethernet
    } else if name.starts_with("tun") || name.starts_with("tap") {
        InterfaceKind::Virtual
    } else if name.starts_with("tun") {
        InterfaceKind::Tunnel
    } else {
        InterfaceKind::Other(name.to_string())
    };

    // Get IP addresses
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();

    if let Ok(addr_dir) = fs::read_dir(base_path.join("address")) {
        for entry in addr_dir {
            let entry = entry?;
            let addr = fs::read_to_string(entry.path())?;
            let addr = addr.trim();

            if let Ok(ip) = addr.parse::<IpAddr>() {
                match ip {
                    IpAddr::V4(ipv4_addr) => {
                        ipv4.push(IpNetwork::new(IpAddr::V4(ipv4_addr), 32));
                    }
                    IpAddr::V6(ipv6_addr) => {
                        ipv6.push(IpNetwork::new(IpAddr::V6(ipv6_addr), 128));
                    }
                }
            }
        }
    }

    // Get interface statistics
    let stats = get_interface_stats(name)?;

    Ok(Interface {
        name: name.to_string(),
        index: 0, // TODO: Get from netlink
        mac_address,
        mtu,
        is_up: flags.contains(InterfaceFlags::IFF_UP),
        is_running: flags.contains(InterfaceFlags::IFF_RUNNING),
        kind,
        ipv4,
        ipv6,
        stats,
    })
}

/// Get the default network interface
pub fn get_default_interface() -> Result<Interface> {
    // Try to get the interface with the default route
    let output = std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()?;

    let output = String::from_utf8_lossy(&output.stdout);
    if let Some(iface) = output.lines().next() {
        if let Some(name) = iface.split_whitespace().nth(4) {
            return Interface::by_name(name);
        }
    }

    // Fallback to the first non-loopback interface
    let interfaces = list_interfaces()?;
    interfaces
        .into_iter()
        .find(|iface| iface.kind != InterfaceKind::Loopback)
        .ok_or_else(|| NetworkError::Platform("No default interface found".to_string()))
}

/// Get statistics for a network interface
pub fn get_interface_stats(name: &str) -> Result<InterfaceStats> {
    let stats_path = Path::new("/sys/class/net").join(name).join("statistics");

    let read_stat = |file: &str| -> Result<u64> {
        Ok(fs::read_to_string(stats_path.join(file))?.trim().parse()?)
    };

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0));

    Ok(InterfaceStats {
        rx_bytes: read_stat("rx_bytes")?,
        tx_bytes: read_stat("tx_bytes")?,
        rx_packets: read_stat("rx_packets")?,
        tx_packets: read_stat("tx_packets")?,
        rx_errors: read_stat("rx_errors")?,
        tx_errors: read_stat("tx_errors")?,
        rx_dropped: read_stat("rx_dropped")?,
        tx_dropped: read_stat("tx_dropped")?,
        rx_fifo_errors: read_stat("rx_fifo_errors")?,
        tx_fifo_errors: read_stat("tx_fifo_errors")?,
        rx_frame_errors: read_stat("rx_frame_errors")?,
        tx_collisions: read_stat("tx_collisions")?,
        rx_compressed: read_stat("rx_compressed")?,
        tx_compressed: read_stat("tx_compressed")?,
        multicast: read_stat("multicast")?,
        timestamp,
    })
}
