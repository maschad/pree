use std::net::SocketAddr;
use std::time::Duration;

use crate::types::Protocol;

use crate::types::SocketState;
use crate::NetworkError;
use crate::NetworkResult as Result;

/// Get the system's maximum number of open sockets
///
/// # Errors
/// Returns an error if reading system limits fails
pub fn get_system_socket_limit() -> Result<usize> {
    #[cfg(target_os = "linux")]
    {
        use std::fs::read_to_string;
        let limit = read_to_string("/proc/sys/fs/file-max")?;
        Ok(limit.trim().parse()?)
    }
    #[cfg(target_os = "windows")]
    {
        // Windows doesn't have a direct equivalent, estimate based on system resources
        use winapi::um::sysinfoapi::*;
        let mut info: SYSTEM_INFO = unsafe { std::mem::zeroed() };
        unsafe { GetSystemInfo(&mut info) };
        Ok((info.dwNumberOfProcessors as usize) * 1024)
    }
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let output = Command::new("sysctl")
            .args(["-n", "kern.maxfiles"])
            .output()?;
        let limit = String::from_utf8_lossy(&output.stdout);
        Ok(limit.trim().parse()?)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        Err(NetworkError::UnsupportedPlatform)
    }
}

/// Get a list of available ports in the system
///
/// # Errors
/// Returns an error if socket information cannot be retrieved
pub fn get_available_ports() -> Result<Vec<u16>> {
    let sockets = get_sockets_info()?;
    let used_ports: std::collections::HashSet<u16> =
        sockets.iter().map(|s| s.local_addr.port()).collect();

    let mut available = Vec::new();
    for port in 1024..65535 {
        if !used_ports.contains(&port) {
            available.push(port);
        }
    }

    Ok(available)
}

/// Check if a specific port is available for binding
///
/// # Errors
/// Returns an error if socket information cannot be retrieved
pub fn is_port_available(port: u16) -> Result<bool> {
    let sockets = get_sockets_info()?;
    Ok(!sockets.iter().any(|s| s.local_addr.port() == port))
}

/// Get the ephemeral port range for the system
///
/// # Errors
/// Returns an error if system port range information cannot be retrieved
pub fn get_ephemeral_port_range() -> Result<(u16, u16)> {
    #[cfg(target_os = "linux")]
    {
        use std::fs::read_to_string;
        let range = read_to_string("/proc/sys/net/ipv4/ip_local_port_range")?;
        let parts: Vec<&str> = range.split_whitespace().collect();
        if parts.len() != 2 {
            return Err(NetworkError::InvalidData);
        }
        Ok((parts[0].parse()?, parts[1].parse()?))
    }
    #[cfg(target_os = "windows")]
    {
        // Windows uses 49152-65535 for ephemeral ports
        Ok((49152, 65535))
    }
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let output = Command::new("sysctl")
            .args([
                "-n",
                "net.inet.ip.portrange.first",
                "net.inet.ip.portrange.last",
            ])
            .output()?;
        let range = String::from_utf8_lossy(&output.stdout);
        let parts: Vec<&str> = range.split_whitespace().collect();
        if parts.len() != 2 {
            return Err(NetworkError::InvalidData);
        }
        Ok((parts[0].parse()?, parts[1].parse()?))
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        Err(NetworkError::UnsupportedPlatform)
    }
}

#[derive(Debug, Clone)]
pub struct SocketStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub errors: u64,
    pub retransmits: u64,
    pub rtt: Option<Duration>,
    pub congestion_window: Option<u32>,
    pub send_queue_size: Option<u32>,
    pub receive_queue_size: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct SocketInfo {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub state: SocketState,
    pub protocol: Protocol,
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
    pub stats: Option<SocketStats>,
}

/// Get information about all system sockets
///
/// # Errors
/// Returns an error if socket information cannot be retrieved
pub fn get_sockets_info() -> Result<Vec<SocketInfo>> {
    #[cfg(target_os = "linux")]
    {
        linux::get_sockets_info()
    }
    #[cfg(target_os = "windows")]
    {
        windows::get_sockets_info()
    }
    #[cfg(target_os = "macos")]
    {
        Ok(macos::get_sockets_info())
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        Err(NetworkError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;

    #[test]
    fn test_process_info_retrieval() {
        let sockets = get_sockets_info().unwrap();
        assert!(!sockets.is_empty());

        for socket in sockets {
            if let Some(pid) = socket.process_id {
                #[cfg(target_os = "linux")]
                let process_info = linux::get_process_info(pid);
                #[cfg(target_os = "windows")]
                let process_info = windows::get_process_info(pid);
                #[cfg(target_os = "macos")]
                let process_info = macos::get_process_info(pid);
                #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
                let process_info = None;

                assert!(
                    process_info.is_some(),
                    "Failed to get process info for PID {pid}"
                );
                let info = process_info.unwrap();

                assert_eq!(info.pid, pid);
                assert!(info.name.as_ref().is_some_and(|n| !n.is_empty()));
                assert!(info.cmdline.is_some());

                if let Some(start_time) = info.start_time {
                    assert!(start_time <= SystemTime::now());
                }

                if let Some(memory) = info.memory_usage {
                    assert!(memory > 0);
                }
            }
        }
    }

    #[test]
    fn test_socket_info_consistency() {
        let sockets = get_sockets_info().unwrap();
        assert!(!sockets.is_empty());

        for socket in sockets {
            // Test local address
            assert!(socket.local_addr.port() > 0);

            // Test protocol
            assert!(matches!(socket.protocol, Protocol::Tcp | Protocol::Udp));

            // Test state
            assert!(matches!(
                socket.state,
                SocketState::Established
                    | SocketState::Listen
                    | SocketState::Connecting
                    | SocketState::Closing
                    | SocketState::Closed
                    | SocketState::Bound
                    | SocketState::Unknown(_)
            ));

            // Test process info consistency
            if socket.process_id.is_some() {
                if let Some(name) = &socket.process_name {
                    assert!(!name.is_empty());
                }
            }
        }
    }

    #[test]
    fn test_socket_stats() {
        let sockets = get_sockets_info().unwrap();
        assert!(!sockets.is_empty());

        for socket in sockets {
            if let Some(stats) = socket.stats {
                // Test TCP-specific stats if available
                if socket.protocol == Protocol::Tcp {
                    if let Some(rtt) = stats.rtt {
                        assert!(rtt > Duration::from_micros(0));
                    }
                    if let Some(cwnd) = stats.congestion_window {
                        assert!(cwnd > 0);
                    }
                }
            }
        }
    }

    #[test]
    fn test_platform_specific_implementation() {
        #[cfg(target_os = "linux")]
        {
            let sockets = linux::get_sockets_info().unwrap();
            assert!(!sockets.is_empty());
            for socket in sockets {
                assert!(socket.local_addr.port() > 0);
                if let Some(pid) = socket.process_id {
                    let process_info = linux::get_process_info(pid);
                    assert!(process_info.is_some());
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            let sockets = windows::get_sockets_info().unwrap();
            assert!(!sockets.is_empty());
            for socket in sockets {
                assert!(socket.local_addr.port() > 0);
                if let Some(pid) = socket.process_id {
                    let process_info = windows::get_process_info(pid);
                    assert!(process_info.is_some());
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            let sockets = macos::get_sockets_info();
            assert!(!sockets.is_empty());
            for socket in sockets {
                assert!(socket.local_addr.port() > 0);
                if let Some(pid) = socket.process_id {
                    let process_info = macos::get_process_info(pid);
                    assert!(process_info.is_some());
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::fs::{self, File};
    use std::io::{BufRead, BufReader};
    use std::path::Path;
    use std::time::{Duration, UNIX_EPOCH};

    pub fn get_sockets_info() -> Result<Vec<SocketInfo>> {
        let mut sockets = Vec::new();

        // Read TCP sockets from /proc/net/tcp
        if let Ok(file) = File::open("/proc/net/tcp") {
            let reader = BufReader::new(file);
            for line in reader.lines().skip(1) {
                if let Ok(line) = line {
                    if let Some(mut socket) = parse_tcp_line(&line) {
                        // Get process info from inode
                        if let Some(inode) = get_inode_from_line(&line) {
                            if let Some((pid, name)) = get_process_from_inode(inode) {
                                socket.process_id = Some(pid);
                                socket.process_name = Some(name);
                            }
                        }
                        sockets.push(socket);
                    }
                }
            }
        }

        // Read UDP sockets from /proc/net/udp
        if let Ok(file) = File::open("/proc/net/udp") {
            let reader = BufReader::new(file);
            for line in reader.lines().skip(1) {
                if let Ok(line) = line {
                    if let Some(mut socket) = parse_udp_line(&line) {
                        // Get process info from inode
                        if let Some(inode) = get_inode_from_line(&line) {
                            if let Some((pid, name)) = get_process_from_inode(inode) {
                                socket.process_id = Some(pid);
                                socket.process_name = Some(name);
                            }
                        }
                        sockets.push(socket);
                    }
                }
            }
        }

        Ok(sockets)
    }

    // ... rest of linux module implementation ...
}

#[cfg(target_os = "macos")]
mod macos {
    use libc::sockaddr_in;
    use std::mem;
    use std::net::{IpAddr, SocketAddr};
    use std::os::raw::{c_int, c_void};
    use std::time::{Duration, UNIX_EPOCH};

    use crate::error::NetworkError;
    use crate::types::Protocol;
    use crate::{ProcessInfo, SocketState};

    use super::{SocketInfo, SocketStats};

    // TCP control constants
    const TCPCTL_PCBLIST: c_int = 1;
    const TCP_INFO: c_int = 0x20; // TCP_INFO socket option

    #[repr(C)]
    struct xinpcb {
        next: *mut xinpcb,
        prev: *mut xinpcb,
        socket: *mut xsocket,
        laddr: sockaddr_in,
        faddr: sockaddr_in,
        lport: u16,
        fport: u16,
        pid: i32,
    }

    #[repr(C)]
    struct xsocket {
        so_pcb: *mut c_void,
        so_state: u16,
    }

    // TCP state constants
    const TCP_ESTABLISHED: u16 = 1;
    const TCP_SYN_SENT: u16 = 2;
    const TCP_SYN_RECV: u16 = 3;
    const TCP_FIN_WAIT1: u16 = 4;
    const TCP_FIN_WAIT2: u16 = 5;
    const TCP_TIME_WAIT: u16 = 6;
    const TCP_CLOSE: u16 = 7;
    const TCP_CLOSE_WAIT: u16 = 8;
    const TCP_LAST_ACK: u16 = 9;
    const TCP_LISTEN: u16 = 10;
    const TCP_CLOSING: u16 = 11;

    // TCP info structure
    #[repr(C)]
    struct TCP_INFO {
        state: u8,
        ca_state: u8,
        retransmits: u8,
        probes: u8,
        backoff: u8,
        options: u8,
        snd_wscale: u8,
        rcv_wscale: u8,
        rto: u32,
        ato: u32,
        snd_mss: u32,
        rcv_mss: u32,
        unacked: u32,
        sacked: u32,
        lost: u32,
        retrans: u32,
        fackets: u32,
        last_data_sent: u32,
        last_ack_sent: u32,
        last_data_recv: u32,
        last_ack_recv: u32,
        pmtu: u32,
        rcv_ssthresh: u32,
        rtt: u32,
        rttvar: u32,
        snd_ssthresh: u32,
        snd_cwnd: u32,
        advmss: u32,
        reordering: u32,
        rcv_rtt: u32,
        rcv_space: u32,
        total_retrans: u32,
    }

    pub fn get_sockets_info() -> Vec<SocketInfo> {
        let mut sockets = Vec::new();

        // Get TCP sockets
        if let Ok(tcp_sockets) = get_tcp_sockets() {
            sockets.extend(tcp_sockets);
        }

        // Get UDP sockets
        if let Ok(udp_sockets) = get_udp_sockets() {
            sockets.extend(udp_sockets);
        }

        sockets
    }

    #[allow(clippy::too_many_lines)]
    fn get_tcp_sockets() -> Result<Vec<SocketInfo>, NetworkError> {
        let mut size = 0;
        let mut mib = [
            libc::CTL_NET,
            libc::AF_INET,
            libc::IPPROTO_TCP,
            TCPCTL_PCBLIST,
            0,
        ];

        // Get required buffer size
        unsafe {
            if libc::sysctl(
                mib.as_mut_ptr(),
                u32::try_from(mib.len()).unwrap(),
                std::ptr::null_mut(),
                &mut size,
                std::ptr::null_mut(),
                0,
            ) != 0
            {
                return Err(NetworkError::OsError(
                    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
                ));
            }
        }

        // Allocate buffer and get socket info
        let mut buffer = vec![0u8; size];
        unsafe {
            if libc::sysctl(
                mib.as_mut_ptr(),
                u32::try_from(mib.len()).unwrap(),
                buffer.as_mut_ptr().cast::<c_void>(),
                &mut size,
                std::ptr::null_mut(),
                0,
            ) != 0
            {
                return Err(NetworkError::OsError(
                    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
                ));
            }
        }

        let mut sockets = Vec::new();
        let mut offset = 0;

        while offset < size {
            #[allow(clippy::cast_ptr_alignment)]
            let pcb = unsafe { &*buffer.as_ptr().add(offset).cast::<xinpcb>() };
            let local_addr = SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(
                    pcb.laddr.sin_addr.s_addr,
                ))),
                u16::from_be(pcb.lport),
            );

            let remote_addr = SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(
                    pcb.faddr.sin_addr.s_addr,
                ))),
                u16::from_be(pcb.fport),
            );

            let socket = unsafe { &*pcb.socket.cast::<xsocket>() };
            let state = match socket.so_state {
                TCP_ESTABLISHED => SocketState::Established,
                TCP_SYN_SENT | TCP_SYN_RECV => SocketState::Connecting,
                TCP_FIN_WAIT1 | TCP_FIN_WAIT2 | TCP_TIME_WAIT | TCP_CLOSE_WAIT | TCP_LAST_ACK
                | TCP_CLOSING => SocketState::Closing,
                TCP_CLOSE => SocketState::Closed,
                TCP_LISTEN => SocketState::Listen,
                _ => SocketState::Unknown("Unknown TCP state".to_string()),
            };

            let process_info = if pcb.pid > 0 {
                Some(ProcessInfo {
                    #[allow(clippy::cast_sign_loss)]
                    pid: pcb.pid as u32,
                    name: None,
                    cmdline: None,
                    uid: None,
                    start_time: None,
                    memory_usage: None,
                    cpu_usage: None,
                    user: None,
                })
            } else {
                None
            };

            sockets.push(SocketInfo {
                local_addr,
                remote_addr,
                state,
                protocol: Protocol::Tcp,
                process_id: process_info.clone().map(|info| info.pid),
                process_name: None,
                stats: get_socket_stats(pcb.socket),
            });

            sockets.push(SocketInfo {
                local_addr,
                remote_addr,
                state: SocketState::Established, // UDP sockets are always in Established state
                protocol: Protocol::Udp,
                process_id: process_info.map(|info| info.pid),
                process_name: None,
                stats: None, // UDP doesn't have TCP-specific stats
            });

            offset += mem::size_of::<xinpcb>();
        }

        Ok(sockets)
    }

    fn get_udp_sockets() -> Result<Vec<SocketInfo>, NetworkError> {
        let mut size = 0;
        let mut mib = [
            libc::CTL_NET,
            libc::AF_INET,
            libc::IPPROTO_UDP,
            TCPCTL_PCBLIST,
            0,
        ];

        // Get required buffer size from sysctl
        unsafe {
            if libc::sysctl(
                mib.as_mut_ptr(),
                u32::try_from(mib.len()).unwrap(),
                std::ptr::null_mut(),
                &mut size,
                std::ptr::null_mut(),
                0,
            ) != 0
            {
                return Err(NetworkError::OsError(
                    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
                ));
            }
        }

        // Allocate buffer and get socket info from sysctl
        let mut buffer = vec![0u8; size];
        unsafe {
            if libc::sysctl(
                mib.as_mut_ptr(),
                u32::try_from(mib.len()).unwrap(),
                buffer.as_mut_ptr().cast::<c_void>(),
                &mut size,
                std::ptr::null_mut(),
                0,
            ) != 0
            {
                return Err(NetworkError::OsError(
                    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
                ));
            }
        }

        let mut sockets = Vec::new();
        let mut offset = 0;

        while offset < size {
            #[allow(clippy::cast_ptr_alignment)]
            let pcb = unsafe { &*buffer.as_ptr().add(offset).cast::<xinpcb>() };
            let local_addr = SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(
                    pcb.laddr.sin_addr.s_addr,
                ))),
                u16::from_be(pcb.lport),
            );

            let remote_addr = SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(
                    pcb.faddr.sin_addr.s_addr,
                ))),
                u16::from_be(pcb.fport),
            );

            let socket = unsafe { &*pcb.socket.cast::<xsocket>() };
            let state = match socket.so_state {
                TCP_ESTABLISHED => SocketState::Established,
                TCP_SYN_SENT | TCP_SYN_RECV => SocketState::Connecting,
                TCP_FIN_WAIT1 | TCP_FIN_WAIT2 | TCP_TIME_WAIT | TCP_CLOSE_WAIT | TCP_LAST_ACK
                | TCP_CLOSING => SocketState::Closing,
                TCP_CLOSE => SocketState::Closed,
                TCP_LISTEN => SocketState::Listen,
                _ => SocketState::Unknown("Unknown TCP state".to_string()),
            };

            let process_info = if pcb.pid > 0 {
                Some(ProcessInfo {
                    #[allow(clippy::cast_sign_loss)]
                    pid: pcb.pid as u32,
                    name: None,
                    cmdline: None,
                    uid: None,
                    start_time: None,
                    memory_usage: None,
                    cpu_usage: None,
                    user: None,
                })
            } else {
                None
            };

            sockets.push(SocketInfo {
                local_addr,
                remote_addr,
                state,
                protocol: Protocol::Udp,
                process_id: process_info.map(|info| info.pid),
                process_name: None,
                stats: None, // UDP doesn't have TCP-specific stats
            });

            offset += mem::size_of::<xinpcb>();
        }

        Ok(sockets)
    }

    fn get_socket_stats(socket: *const xsocket) -> Option<SocketStats> {
        unsafe {
            let socket = &*socket;
            let mut tcp_info: TCP_INFO = mem::zeroed();
            let mut len = mem::size_of::<TCP_INFO>();

            if libc::getsockopt(
                socket.so_pcb as i32,
                libc::IPPROTO_TCP,
                TCP_INFO,
                (&raw mut tcp_info).cast::<c_void>(),
                (&raw mut len).cast::<u32>(),
            ) == 0
            {
                Some(SocketStats {
                    bytes_sent: u64::from(tcp_info.snd_cwnd),
                    bytes_received: u64::from(tcp_info.rcv_mss),
                    packets_sent: u64::from(tcp_info.snd_ssthresh),
                    packets_received: u64::from(tcp_info.rcv_ssthresh),
                    errors: u64::from(tcp_info.retransmits),
                    retransmits: u64::from(tcp_info.retransmits),
                    rtt: Some(Duration::from_micros(u64::from(tcp_info.rtt))),
                    congestion_window: Some(tcp_info.snd_cwnd),
                    send_queue_size: Some(tcp_info.snd_mss),
                    receive_queue_size: Some(tcp_info.rcv_mss),
                })
            } else {
                None
            }
        }
    }
    #[allow(clippy::cast_sign_loss)]
    #[allow(dead_code)]
    pub fn get_process_info(pid: u32) -> Option<ProcessInfo> {
        use std::process::Command;

        // Get process name using ps
        let output = Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "comm="])
            .output()
            .ok()?;

        let name = String::from_utf8_lossy(&output.stdout).trim().to_string();

        // Get user using ps
        let output = Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "user="])
            .output()
            .ok()?;

        let user = String::from_utf8_lossy(&output.stdout).trim().to_string();

        // Get memory usage using ps
        let output = Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "rss="])
            .output()
            .ok()?;

        let memory_usage = String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<u64>()
            .ok()
            .map(|kb| kb * 1024); // Convert KB to bytes

        // Get CPU usage using ps
        let output = Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "%cpu="])
            .output()
            .ok()?;

        let cpu_usage = String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<f32>()
            .ok();

        // Get process start time using ps
        let output = Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "lstart="])
            .output()
            .ok()?;

        let start_time = String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<i64>()
            .ok()
            .map(|timestamp| UNIX_EPOCH + Duration::from_secs(timestamp as u64));

        Some(ProcessInfo {
            pid,
            name: Some(name),
            cmdline: None,
            uid: None,
            start_time,
            memory_usage,
            #[allow(clippy::cast_possible_truncation)]
            cpu_usage: cpu_usage.map(|usage| usage as u64),
            user: Some(user),
        })
    }

    // Get system-wide socket statistics
    ///
    /// # Errors
    /// Returns an error if socket information cannot be retrieved
    #[allow(dead_code)]
    pub fn get_system_socket_stats() -> SocketStats {
        let mut stats = SocketStats {
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            errors: 0,
            retransmits: 0,
            rtt: None,
            congestion_window: None,
            send_queue_size: None,
            receive_queue_size: None,
        };

        // Get TCP sockets
        if let Ok(tcp_sockets) = get_tcp_sockets() {
            for socket in tcp_sockets {
                if let Some(socket_stats) = socket.stats {
                    stats.bytes_sent += socket_stats.bytes_sent;
                    stats.bytes_received += socket_stats.bytes_received;
                    stats.packets_sent += socket_stats.packets_sent;
                    stats.packets_received += socket_stats.packets_received;
                    stats.errors += socket_stats.errors;
                    stats.retransmits += socket_stats.retransmits;
                }
            }
        }

        // Get UDP sockets
        if let Ok(udp_sockets) = get_udp_sockets() {
            for socket in udp_sockets {
                if let Some(socket_stats) = socket.stats {
                    stats.bytes_sent += socket_stats.bytes_sent;
                    stats.bytes_received += socket_stats.bytes_received;
                    stats.packets_sent += socket_stats.packets_sent;
                    stats.packets_received += socket_stats.packets_received;
                    stats.errors += socket_stats.errors;
                }
            }
        }

        stats
    }

    // ... rest of macos module implementation ...
}
