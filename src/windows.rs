use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ipnetwork::IpNetwork;
use mac_address::MacAddress;
use winapi::shared::winerror::ERROR_SUCCESS;
use winapi::um::iphlpapi::{
    GetAdaptersAddresses, GetIfTable2, GAA_FLAG_INCLUDE_PREFIX, IF_TYPE_ETHERNET_CSMACD,
    IF_TYPE_IEEE80211, IF_TYPE_SOFTWARE_LOOPBACK, IF_TYPE_TUNNEL, IP_ADAPTER_ADDRESSES_LH,
    IP_ADAPTER_UNICAST_ADDRESS_LH, MIB_IFROW2, MIB_IFTABLE2,
};
use winapi::um::ws2def::{AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6};

use crate::interface::{Interface, InterfaceKind, InterfaceStats};
use crate::{NetworkError, Result};

/// List all available network interfaces
pub fn list_interfaces() -> Result<Vec<Interface>> {
    let mut interfaces = Vec::new();

    // Get adapter addresses
    let mut size = 0;
    let mut ret = unsafe {
        GetAdaptersAddresses(
            AF_INET as u32,
            GAA_FLAG_INCLUDE_PREFIX,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut size,
        )
    };

    if ret != ERROR_SUCCESS && ret != 234 {
        // ERROR_BUFFER_OVERFLOW
        return Err(NetworkError::Platform(format!(
            "Failed to get adapter addresses: {}",
            ret
        )));
    }

    let mut buffer = vec![0u8; size as usize];
    let adapter_addresses = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

    ret = unsafe {
        GetAdaptersAddresses(
            AF_INET as u32,
            GAA_FLAG_INCLUDE_PREFIX,
            ptr::null_mut(),
            adapter_addresses,
            &mut size,
        )
    };

    if ret != ERROR_SUCCESS {
        return Err(NetworkError::Platform(format!(
            "Failed to get adapter addresses: {}",
            ret
        )));
    }

    // Get interface table
    let mut if_table: *mut MIB_IFTABLE2 = ptr::null_mut();
    ret = unsafe { GetIfTable2(&mut if_table) };

    if ret != ERROR_SUCCESS {
        return Err(NetworkError::Platform(format!(
            "Failed to get interface table: {}",
            ret
        )));
    }

    // Process each adapter
    let mut current = adapter_addresses;
    while !current.is_null() {
        let adapter = unsafe { &*current };

        // Get interface type
        let kind = match unsafe { adapter.IfType } {
            IF_TYPE_SOFTWARE_LOOPBACK => InterfaceKind::Loopback,
            IF_TYPE_ETHERNET_CSMACD => InterfaceKind::Ethernet,
            IF_TYPE_IEEE80211 => InterfaceKind::Wireless,
            IF_TYPE_TUNNEL => InterfaceKind::Tunnel,
            _ => InterfaceKind::Other(format!("Type {}", unsafe { adapter.IfType })),
        };

        // Get MAC address
        let mac_address = if unsafe { adapter.PhysicalAddressLength } == 6 {
            let mac = unsafe { adapter.PhysicalAddress };
            Some(MacAddress::new([
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            ]))
        } else {
            None
        };

        // Get IP addresses
        let mut ipv4 = Vec::new();
        let mut ipv6 = Vec::new();

        let mut current_addr = unsafe { adapter.FirstUnicastAddress };
        while !current_addr.is_null() {
            let addr = unsafe { &*current_addr };
            let sock_addr = unsafe { addr.Address.lpSockaddr };

            match unsafe { (*sock_addr).sa_family } as i32 {
                AF_INET => {
                    let addr = unsafe { *(sock_addr as *const SOCKADDR_IN) };
                    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.S_un.S_addr));
                    ipv4.push(IpNetwork::new(
                        IpAddr::V4(ip),
                        addr.sin_addr.S_un.S_addr.count_ones() as u8,
                    )?);
                }
                AF_INET6 => {
                    let addr = unsafe { *(sock_addr as *const SOCKADDR_IN6) };
                    let ip = Ipv6Addr::from(addr.sin6_addr.u.Byte);
                    ipv6.push(IpNetwork::new(IpAddr::V6(ip), 128)?);
                }
                _ => {}
            }

            current_addr = unsafe { addr.Next };
        }

        // Get interface statistics
        let mut stats = InterfaceStats::default();
        if !if_table.is_null() {
            let table = unsafe { &*if_table };
            for i in 0..table.dwNumEntries {
                let row = unsafe { &*table.Table.as_ptr().add(i as usize) };
                if row.InterfaceLuid.Value == unsafe { adapter.Luid.Value } {
                    stats.rx_bytes = row.InOctets;
                    stats.tx_bytes = row.OutOctets;
                    stats.rx_packets = row.InUcastPkts + row.InNUcastPkts;
                    stats.tx_packets = row.OutUcastPkts + row.OutNUcastPkts;
                    stats.rx_errors = row.InErrors;
                    stats.tx_errors = row.OutErrors;
                    stats.rx_dropped = row.InDiscards;
                    stats.tx_dropped = row.OutDiscards;
                    break;
                }
            }
        }

        // Get interface name
        let name = unsafe {
            std::ffi::CStr::from_ptr(adapter.AdapterName)
                .to_string_lossy()
                .into_owned()
        };

        interfaces.push(Interface {
            name,
            index: unsafe { adapter.IfIndex },
            mac_address,
            mtu: unsafe { adapter.Mtu },
            is_up: unsafe { adapter.OperStatus } == 1, // IfOperStatusUp
            is_running: unsafe { adapter.OperStatus } == 1,
            kind,
            ipv4,
            ipv6,
            stats,
        });

        current = unsafe { adapter.Next };
    }

    // Free the interface table
    if !if_table.is_null() {
        unsafe { winapi::um::iphlpapi::FreeMibTable(if_table as *mut _) };
    }

    Ok(interfaces)
}

/// Get the default network interface
pub fn get_default_interface() -> Result<Interface> {
    let interfaces = list_interfaces()?;

    // Try to find the first non-loopback interface that's up
    interfaces
        .into_iter()
        .find(|iface| iface.kind != InterfaceKind::Loopback && iface.is_up)
        .ok_or_else(|| NetworkError::Platform("No default interface found".to_string()))
}

/// Get statistics for a network interface
pub fn get_interface_stats(name: &str) -> Result<InterfaceStats> {
    let mut if_table: *mut MIB_IFTABLE2 = ptr::null_mut();
    let ret = unsafe { GetIfTable2(&mut if_table) };

    if ret != ERROR_SUCCESS {
        return Err(NetworkError::Platform(format!(
            "Failed to get interface table: {}",
            ret
        )));
    }

    let mut stats = InterfaceStats::default();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0));

    if !if_table.is_null() {
        let table = unsafe { &*if_table };
        for i in 0..table.dwNumEntries {
            let row = unsafe { &*table.Table.as_ptr().add(i as usize) };
            let row_name = unsafe {
                std::ffi::CStr::from_ptr(row.wszName.as_ptr())
                    .to_string_lossy()
                    .into_owned()
            };

            if row_name == name {
                stats.rx_bytes = row.InOctets;
                stats.tx_bytes = row.OutOctets;
                stats.rx_packets = row.InUcastPkts + row.InNUcastPkts;
                stats.tx_packets = row.OutUcastPkts + row.OutNUcastPkts;
                stats.rx_errors = row.InErrors;
                stats.tx_errors = row.OutErrors;
                stats.rx_dropped = row.InDiscards;
                stats.tx_dropped = row.OutDiscards;
                stats.timestamp = timestamp;
                break;
            }
        }

        unsafe { winapi::um::iphlpapi::FreeMibTable(if_table as *mut _) };
    }

    Ok(stats)
}
