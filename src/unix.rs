use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(target_os = "linux")]
use nix::net::if_::InterfaceFlags;

use crate::dns::DnsConfig;
use crate::interface::{Interface, InterfaceKind, InterfaceStats};
use crate::routing::{Route, RoutingTable};
use crate::types::IpNetwork;
#[cfg(target_os = "linux")]
use crate::types::MacAddress;
use crate::Error;
#[cfg(target_os = "linux")]
use crate::Result;

pub type UnixResult<T> = std::result::Result<T, Error>;

/// List all available network interfaces
///
/// # Errors
/// Returns an error if reading interface information fails
pub fn list_interfaces() -> UnixResult<Vec<Interface>> {
    #[cfg(target_os = "linux")]
    {
        list_interfaces_linux()
    }
    #[cfg(target_os = "macos")]
    {
        list_interfaces_macos()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(Error::unsupported_platform("interface listing"))
    }
}

#[cfg(target_os = "linux")]
fn list_interfaces_linux() -> UnixResult<Vec<Interface>> {
    let mut interfaces = Vec::new();

    // Read from /sys/class/net
    let net_dir = Path::new("/sys/class/net");
    for entry in fs::read_dir(net_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();

        if let Ok(interface) = get_interface_info_linux(&name) {
            interfaces.push(interface);
        }
    }

    Ok(interfaces)
}

/// Get information about a specific interface on Linux
#[cfg(target_os = "linux")]
fn get_interface_info_linux(name: &str) -> UnixResult<Interface> {
    let base_path = Path::new("/sys/class/net").join(name);

    // Read interface flags
    let flags = fs::read_to_string(base_path.join("flags"))?;
    let flags = u32::from_str_radix(flags.trim(), 16)?;
    #[allow(clippy::cast_possible_wrap)]
    let flags = InterfaceFlags::from_bits_truncate(flags as i32);

    // Read MTU
    let mtu = fs::read_to_string(base_path.join("mtu"))?.trim().parse()?;

    // Read MAC address
    let mac = fs::read_to_string(base_path.join("address"))?;
    let mac = mac.trim();
    let mac_address = if mac == "00:00:00:00:00:00" {
        None
    } else {
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
    let stats = get_interface_stats_linux(name)?;

    Ok(Interface {
        name: name.to_string(),
        index: 0,
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
///
/// # Errors
/// Returns an error if the default interface cannot be found
pub fn get_default_interface() -> UnixResult<Interface> {
    // Fallback to the first non-loopback interface
    let interfaces = list_interfaces()?;
    interfaces
        .into_iter()
        .find(|iface| iface.kind != InterfaceKind::Loopback)
        .ok_or_else(|| Error::InterfaceNotFound {
            name: "default".to_string(),
        })
}

/// Get statistics for a network interface on Linux
///
/// # Errors
/// Returns an error if reading interface statistics fails
#[cfg(target_os = "linux")]
pub fn get_interface_stats_linux(name: &str) -> UnixResult<InterfaceStats> {
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

/// Get the system routing table
///
/// # Errors
/// Returns an error if reading the routing table fails
///
/// # Panics
/// Panics if the routing table output cannot be parsed
pub fn get_routing_table() -> UnixResult<RoutingTable> {
    let output = std::process::Command::new("ip")
        .args(["route", "show"])
        .output()?;

    let mut routes = Vec::new();
    let mut default_gateway = None;

    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let mut route = Route {
            destination: IpNetwork::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
            gateway: None,
            interface: String::new(),
            metric: 0,
        };

        let mut i = 0;
        while i < parts.len() {
            match *parts.get(i).unwrap() {
                "default" => {
                    route.destination = IpNetwork::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
                }
                "via" => {
                    if i + 1 < parts.len() {
                        if let Ok(ip) = parts[i + 1].parse::<IpAddr>() {
                            route.gateway = Some(ip);
                        }
                        i += 1;
                    }
                }
                "dev" => {
                    if i + 1 < parts.len() {
                        route.interface = parts[i + 1].to_string();
                        i += 1;
                    }
                }
                "metric" => {
                    if i + 1 < parts.len() {
                        if let Ok(metric) = parts[i + 1].parse::<u32>() {
                            route.metric = metric;
                        }
                        i += 1;
                    }
                }
                _ => {
                    if parts[i].contains('/') {
                        if let Ok(net) = parts[i].parse::<IpNetwork>() {
                            route.destination = net;
                        }
                    }
                }
            }
            i += 1;
        }

        if route.destination.is_default() {
            default_gateway = Some(route.clone());
        }
        routes.push(route);
    }

    Ok(RoutingTable {
        routes,
        default_gateway,
    })
}

/// Get all interfaces on macOS using getifaddrs
#[cfg(target_os = "macos")]
#[allow(clippy::cast_ptr_alignment)]
#[allow(clippy::cast_possible_truncation)]
fn list_interfaces_macos() -> UnixResult<Vec<Interface>> {
    use std::collections::HashMap;
    use std::ffi::CStr;
    use std::ptr;

    let mut ifaddrs: *mut libc::ifaddrs = ptr::null_mut();
    let mut interfaces_map: HashMap<String, Interface> = HashMap::new();

    unsafe {
        if libc::getifaddrs(ptr::addr_of_mut!(ifaddrs)) != 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }

        let mut current = ifaddrs;
        while !current.is_null() {
            let ifa = &*current;
            let name = CStr::from_ptr(ifa.ifa_name).to_string_lossy().into_owned();

            // Get or create interface entry
            let interface = interfaces_map.entry(name.clone()).or_insert_with(|| {
                let kind = detect_interface_kind(&name);
                Interface {
                    name: name.clone(),
                    index: 0,
                    mac_address: None,
                    mtu: 1500, // Default MTU
                    is_up: (ifa.ifa_flags & libc::IFF_UP as u32) != 0,
                    is_running: (ifa.ifa_flags & libc::IFF_RUNNING as u32) != 0,
                    kind,
                    ipv4: Vec::new(),
                    ipv6: Vec::new(),
                    stats: InterfaceStats::default(),
                }
            });

            // Add IP addresses
            if !ifa.ifa_addr.is_null() {
                let addr = &*ifa.ifa_addr;
                match i32::from(addr.sa_family) {
                    libc::AF_INET => {
                        let addr = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                        let ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)));
                        let netmask = if ifa.ifa_netmask.is_null() {
                            32
                        } else {
                            let netmask = &*(ifa.ifa_netmask as *const libc::sockaddr_in);
                            #[allow(clippy::cast_possible_truncation)]
                            {
                                u32::from_be(netmask.sin_addr.s_addr).count_ones() as u8
                            }
                        };
                        interface.ipv4.push(IpNetwork::new(ip, netmask));
                    }
                    libc::AF_INET6 => {
                        let addr = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                        let ip = IpAddr::V6(std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr));
                        interface.ipv6.push(IpNetwork::new(ip, 128));
                    }
                    _ => {}
                }
            }

            current = ifa.ifa_next;
        }

        libc::freeifaddrs(ifaddrs);
    }

    // Get statistics for each interface on macOS
    for interface in interfaces_map.values_mut() {
        interface.stats = get_interface_stats_macos(&interface.name);
    }

    Ok(interfaces_map.into_values().collect())
}

#[cfg(target_os = "macos")]
fn detect_interface_kind(name: &str) -> InterfaceKind {
    if name == "lo" || name.starts_with("lo") {
        InterfaceKind::Loopback
    } else if name.starts_with("en") {
        // en0 is usually Wi-Fi, en1 is usually Ethernet on macOS
        InterfaceKind::Wireless // Simplified - could check more details
    } else if name.starts_with("bridge") {
        InterfaceKind::Virtual
    } else if name.starts_with("utun") || name.starts_with("ipsec") {
        InterfaceKind::Tunnel
    } else {
        InterfaceKind::Other(name.to_string())
    }
}

#[cfg(target_os = "macos")]
fn get_interface_stats_macos(_name: &str) -> InterfaceStats {
    // For now, return default stats
    // TODO: Implement using sysctl or IOKit
    InterfaceStats {
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0)),
        ..Default::default()
    }
}

/// Get the system DNS configuration
///
/// # Errors
/// Returns an error if reading /etc/resolv.conf fails
pub fn get_dns_config() -> UnixResult<DnsConfig> {
    let resolv_conf_path = Path::new("/etc/resolv.conf");
    let mut nameservers = Vec::new();
    let mut search_domains = Vec::new();

    if resolv_conf_path.exists() {
        let content = fs::read_to_string(resolv_conf_path)?;

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            match parts[0] {
                "nameserver" => {
                    if parts.len() > 1 {
                        if let Ok(ip) = parts[1].parse::<IpAddr>() {
                            nameservers.push(ip);
                        }
                    }
                }
                "search" | "domain" => {
                    // Add all search domains
                    for domain in &parts[1..] {
                        search_domains.push((*domain).to_string());
                    }
                }
                _ => {}
            }
        }
    }

    Ok(DnsConfig {
        nameservers,
        search_domains,
        timeout: Duration::from_secs(5),
        attempts: 3,
    })
}
