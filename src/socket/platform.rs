use libc::{sockaddr_in, AF_INET, AF_INET6, SOCK_DGRAM, SOCK_STREAM};
use std::io;
use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::os::raw::{c_int, c_void};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::types::Protocol;

use crate::types::{ProcessInfo, SocketState};
use crate::NetworkError;
use crate::NetworkResult as Result;

/// Get the system's maximum number of open sockets
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
            .args(&["-n", "kern.maxfiles"])
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
pub fn is_port_available(port: u16) -> Result<bool> {
    let sockets = get_sockets_info()?;
    Ok(!sockets.iter().any(|s| s.local_addr.port() == port))
}

/// Get the ephemeral port range for the system
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
            .args(&[
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
        macos::get_sockets_info()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        Err(NetworkError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_info_retrieval() {
        let sockets = get_sockets_info().unwrap();
        assert!(!sockets.is_empty());

        for socket in sockets {
            if let Some(pid) = socket.process_id {
                let process_info = match std::env::consts::OS {
                    "linux" => linux::get_process_info(pid),
                    "windows" => windows::get_process_info(pid),
                    "macos" => macos::get_process_info(pid),
                    _ => None,
                };

                assert!(
                    process_info.is_some(),
                    "Failed to get process info for PID {}",
                    pid
                );
                let info = process_info.unwrap();

                assert_eq!(info.pid, pid);
                assert!(!info.name.is_empty());
                assert!(!info.cmdline.is_none());

                if let Some(start_time) = info.start_time {
                    assert!(start_time <= SystemTime::now());
                }

                if let Some(memory) = info.memory_usage {
                    assert!(memory > 0);
                }

                if let Some(cpu) = info.cpu_usage {
                    assert!(cpu >= 0.0 && cpu <= 100.0);
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
            if let Some(_) = socket.process_id {
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
                // Test basic stats
                assert!(stats.bytes_sent >= 0);
                assert!(stats.bytes_received >= 0);
                assert!(stats.packets_sent >= 0);
                assert!(stats.packets_received >= 0);
                assert!(stats.errors >= 0);
                assert!(stats.retransmits >= 0);

                // Test TCP-specific stats if available
                if socket.protocol == Protocol::Tcp {
                    if let Some(rtt) = stats.rtt {
                        assert!(rtt > Duration::from_micros(0));
                    }
                    if let Some(cwnd) = stats.congestion_window {
                        assert!(cwnd > 0);
                    }
                    if let Some(send_q) = stats.send_queue_size {
                        assert!(send_q >= 0);
                    }
                    if let Some(recv_q) = stats.receive_queue_size {
                        assert!(recv_q >= 0);
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
            let sockets = macos::get_sockets_info().unwrap();
            assert!(!sockets.is_empty());
            for socket in sockets {
                assert!(socket.local_addr.port() > 0);
                if let Some(pid) = socket.process_id {
                    let process_info = macos::get_process_info(pid);
                    assert!(process_info.is_some());
                }
                if let Some(stats) = socket.stats {
                    assert!(stats.bytes_sent >= 0);
                    assert!(stats.bytes_received >= 0);
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
    use super::*;
    use libc::{
        c_uchar, c_uint, c_ulong, c_ushort, sockaddr, sockaddr_in, sockaddr_in6, AF_INET, AF_INET6,
        SOCK_DGRAM, SOCK_STREAM,
    };
    use std::mem;
    use std::os::raw::{c_int, c_void};

    // TCP control constants
    const TCPCTL_PCBLIST: c_int = 1;
    const TCP_INFO: c_int = 0x20; // TCP_INFO socket option

    #[repr(C)]
    struct xinpcb {
        inp_next: *mut xinpcb,
        inp_prev: *mut xinpcb,
        inp_socket: *mut xsocket,
        inp_laddr: sockaddr_in,
        inp_faddr: sockaddr_in,
        inp_lport: u16,
        inp_fport: u16,
        inp_pid: i32,
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
        tcpi_state: u8,
        tcpi_ca_state: u8,
        tcpi_retransmits: u8,
        tcpi_probes: u8,
        tcpi_backoff: u8,
        tcpi_options: u8,
        tcpi_snd_wscale: u8,
        tcpi_rcv_wscale: u8,
        tcpi_rto: u32,
        tcpi_ato: u32,
        tcpi_snd_mss: u32,
        tcpi_rcv_mss: u32,
        tcpi_unacked: u32,
        tcpi_sacked: u32,
        tcpi_lost: u32,
        tcpi_retrans: u32,
        tcpi_fackets: u32,
        tcpi_last_data_sent: u32,
        tcpi_last_ack_sent: u32,
        tcpi_last_data_recv: u32,
        tcpi_last_ack_recv: u32,
        tcpi_pmtu: u32,
        tcpi_rcv_ssthresh: u32,
        tcpi_rtt: u32,
        tcpi_rttvar: u32,
        tcpi_snd_ssthresh: u32,
        tcpi_snd_cwnd: u32,
        tcpi_advmss: u32,
        tcpi_reordering: u32,
        tcpi_rcv_rtt: u32,
        tcpi_rcv_space: u32,
        tcpi_total_retrans: u32,
    }

    pub fn get_sockets_info() -> Result<Vec<SocketInfo>> {
        let mut sockets = Vec::new();

        // Get TCP sockets
        if let Ok(tcp_sockets) = get_tcp_sockets() {
            sockets.extend(tcp_sockets);
        }

        // Get UDP sockets
        if let Ok(udp_sockets) = get_udp_sockets() {
            sockets.extend(udp_sockets);
        }

        Ok(sockets)
    }

    fn get_tcp_sockets() -> Result<Vec<SocketInfo>> {
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
                mib.len() as u32,
                std::ptr::null_mut(),
                &mut size,
                std::ptr::null_mut(),
                0,
            ) != 0
            {
                return Err(NetworkError::OsError(
                    io::Error::last_os_error().raw_os_error().unwrap_or(-1),
                ));
            }
        }

        // Allocate buffer and get socket info
        let mut buffer = vec![0u8; size];
        unsafe {
            if libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                buffer.as_mut_ptr() as *mut c_void,
                &mut size,
                std::ptr::null_mut(),
                0,
            ) != 0
            {
                return Err(NetworkError::OsError(
                    io::Error::last_os_error().raw_os_error().unwrap_or(-1),
                ));
            }
        }

        let mut sockets = Vec::new();
        let mut offset = 0;

        while offset < size {
            let pcb = unsafe { &*(buffer.as_ptr().add(offset) as *const xinpcb) };

            let local_addr = SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(
                    pcb.inp_laddr.sin_addr.s_addr,
                ))),
                u16::from_be(pcb.inp_lport),
            );

            let remote_addr = SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(
                    pcb.inp_faddr.sin_addr.s_addr,
                ))),
                u16::from_be(pcb.inp_fport),
            );

            let socket = unsafe { &*pcb.inp_socket };
            let state = match socket.so_state {
                TCP_ESTABLISHED => SocketState::Established,
                TCP_SYN_SENT => SocketState::Connecting,
                TCP_SYN_RECV => SocketState::Connecting,
                TCP_FIN_WAIT1 => SocketState::Closing,
                TCP_FIN_WAIT2 => SocketState::Closing,
                TCP_TIME_WAIT => SocketState::Closing,
                TCP_CLOSE => SocketState::Closed,
                TCP_CLOSE_WAIT => SocketState::Closing,
                TCP_LAST_ACK => SocketState::Closing,
                TCP_LISTEN => SocketState::Listen,
                TCP_CLOSING => SocketState::Closing,
                _ => SocketState::Unknown("Unknown TCP state".to_string()),
            };

            let process_info = if pcb.inp_pid > 0 {
                Some(ProcessInfo {
                    pid: pcb.inp_pid as u32,
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
                stats: get_socket_stats(pcb.inp_socket),
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

    fn get_udp_sockets() -> Result<Vec<SocketInfo>> {
        let mut size = 0;
        let mut mib = [
            libc::CTL_NET,
            libc::AF_INET,
            libc::IPPROTO_UDP,
            TCPCTL_PCBLIST,
            0,
        ];

        // Get required buffer size
        unsafe {
            if libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                std::ptr::null_mut(),
                &mut size,
                std::ptr::null_mut(),
                0,
            ) != 0
            {
                return Err(NetworkError::OsError(
                    io::Error::last_os_error().raw_os_error().unwrap_or(-1),
                ));
            }
        }

        // Allocate buffer and get socket info
        let mut buffer = vec![0u8; size];
        unsafe {
            if libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                buffer.as_mut_ptr() as *mut c_void,
                &mut size,
                std::ptr::null_mut(),
                0,
            ) != 0
            {
                return Err(NetworkError::OsError(
                    io::Error::last_os_error().raw_os_error().unwrap_or(-1),
                ));
            }
        }

        let mut sockets = Vec::new();
        let mut offset = 0;

        while offset < size {
            let pcb = unsafe { &*(buffer.as_ptr().add(offset) as *const xinpcb) };

            let local_addr = SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(
                    pcb.inp_laddr.sin_addr.s_addr,
                ))),
                u16::from_be(pcb.inp_lport),
            );

            let remote_addr = SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(
                    pcb.inp_faddr.sin_addr.s_addr,
                ))),
                u16::from_be(pcb.inp_fport),
            );

            let process_info = if pcb.inp_pid > 0 {
                Some(ProcessInfo {
                    pid: pcb.inp_pid as u32,
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

    fn get_socket_stats(socket: *const xsocket) -> Option<SocketStats> {
        unsafe {
            let socket = &*socket;
            let mut tcp_info: TCP_INFO = mem::zeroed();
            let mut len = mem::size_of::<TCP_INFO>();

            if libc::getsockopt(
                socket.so_pcb as i32,
                libc::IPPROTO_TCP,
                TCP_INFO,
                &mut tcp_info as *mut _ as *mut c_void,
                &mut len as *mut _ as *mut u32,
            ) == 0
            {
                Some(SocketStats {
                    bytes_sent: tcp_info.tcpi_snd_cwnd as u64,
                    bytes_received: tcp_info.tcpi_rcv_mss as u64,
                    packets_sent: tcp_info.tcpi_snd_ssthresh as u64,
                    packets_received: tcp_info.tcpi_rcv_ssthresh as u64,
                    errors: tcp_info.tcpi_retransmits as u64,
                    retransmits: tcp_info.tcpi_retransmits as u64,
                    rtt: Some(Duration::from_micros(tcp_info.tcpi_rtt as u64)),
                    congestion_window: Some(tcp_info.tcpi_snd_cwnd),
                    send_queue_size: Some(tcp_info.tcpi_snd_mss),
                    receive_queue_size: Some(tcp_info.tcpi_rcv_mss),
                })
            } else {
                None
            }
        }
    }

    pub fn get_process_info(pid: u32) -> Option<ProcessInfo> {
        use std::process::Command;

        // Get process name using ps
        let output = Command::new("ps")
            .args(&["-p", &pid.to_string(), "-o", "comm="])
            .output()
            .ok()?;

        let name = String::from_utf8_lossy(&output.stdout).trim().to_string();

        // Get user using ps
        let output = Command::new("ps")
            .args(&["-p", &pid.to_string(), "-o", "user="])
            .output()
            .ok()?;

        let user = String::from_utf8_lossy(&output.stdout).trim().to_string();

        // Get memory usage using ps
        let output = Command::new("ps")
            .args(&["-p", &pid.to_string(), "-o", "rss="])
            .output()
            .ok()?;

        let memory_usage = String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<u64>()
            .ok()
            .map(|kb| kb * 1024); // Convert KB to bytes

        // Get CPU usage using ps
        let output = Command::new("ps")
            .args(&["-p", &pid.to_string(), "-o", "%cpu="])
            .output()
            .ok()?;

        let cpu_usage = String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<f32>()
            .ok();

        // Get process start time using ps
        let output = Command::new("ps")
            .args(&["-p", &pid.to_string(), "-o", "lstart="])
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
            cpu_usage: cpu_usage.map(|usage| usage as u64),
            user: Some(user),
        })
    }

    // Get system-wide socket statistics
    pub fn get_system_socket_stats() -> Result<SocketStats> {
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

        Ok(stats)
    }

    // ... rest of macos module implementation ...
}
