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
    use std::net::TcpListener;
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
        // Create a listening socket
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        println!(
            "Created test socket on port {}",
            listener.local_addr().unwrap().port()
        );

        // Accept connections in a separate thread to keep the socket in LISTEN state
        let _handle = std::thread::spawn(move || {
            let _ = listener.accept();
        });

        // Give the system time to register the socket
        std::thread::sleep(Duration::from_millis(500));

        #[cfg(target_os = "macos")]
        {
            let sockets = macos::get_sockets_info();
            assert!(!sockets.is_empty());
            // Even if we don't find our test socket, we should be able to get socket info
            for socket in sockets {
                assert!(socket.local_addr.port() > 0);
                if let Some(pid) = socket.process_id {
                    let process_info = macos::get_process_info(pid);
                    assert!(process_info.is_some());
                }
            }
        }
        #[cfg(target_os = "linux")]
        {
            let sockets = linux::get_sockets_info();
            assert!(!sockets.is_empty());
            // Even if we don't find our test socket, we should be able to get socket info
            for socket in sockets {
                assert!(socket.local_addr.port() > 0);
                if let Some(pid) = socket.process_id {
                    let process_info = macos::get_process_info(pid);
                    assert!(process_info.is_some());
                }
            }
        }
        #[cfg(target_os = "windows")]
        {
            let sockets = windows::get_sockets_info();
            // Even if we don't find our test socket, we should be able to get socket info
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
#[allow(clippy::all)]
mod linux {
    use super::*;
    use std::fs::File;
    use std::io::{BufRead, BufReader};

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
    use std::net::{IpAddr, SocketAddr};
    use std::process::Command;
    use std::str::FromStr;

    use crate::types::Protocol;
    use crate::{ProcessInfo, SocketState};

    use super::SocketInfo;

    pub fn get_sockets_info() -> Vec<SocketInfo> {
        let mut sockets = Vec::new();

        // Get TCP sockets using netstat
        if let Ok(output) = Command::new("netstat").args(["-an", "-p", "tcp"]).output() {
            let output = String::from_utf8_lossy(&output.stdout);
            for line in output.lines().skip(2) {
                // Skip header lines
                if let Some(socket) = parse_netstat_line(line, Protocol::Tcp) {
                    sockets.push(socket);
                }
            }
        }

        // Get UDP sockets using netstat
        if let Ok(output) = Command::new("netstat").args(["-an", "-p", "udp"]).output() {
            let output = String::from_utf8_lossy(&output.stdout);
            for line in output.lines().skip(2) {
                // Skip header lines
                if let Some(socket) = parse_netstat_line(line, Protocol::Udp) {
                    sockets.push(socket);
                }
            }
        }

        sockets
    }

    fn parse_netstat_line(line: &str, protocol: Protocol) -> Option<SocketInfo> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            return None;
        }

        // Parse local address
        let local_addr = parse_address(parts[3])?;

        // Parse remote address (if connected)
        let remote_addr = if parts.len() > 4 {
            parse_address(parts[4])
                .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0))
        } else {
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
        };

        // Determine state
        let state = if protocol == Protocol::Tcp {
            parts.get(5).map(|s| s.to_lowercase()).map_or_else(
                || SocketState::Unknown("No state information".to_string()),
                |s| match s.as_str() {
                    "established" => SocketState::Established,
                    "listen" => SocketState::Listen,
                    "syn_sent" | "syn_recv" => SocketState::Connecting,
                    "fin_wait1" | "fin_wait2" | "time_wait" | "close_wait" | "last_ack"
                    | "closing" => SocketState::Closing,
                    "closed" => SocketState::Closed,
                    _ => SocketState::Unknown("Unknown TCP state".to_string()),
                },
            )
        } else {
            SocketState::Established // UDP sockets are always in Established state
        };

        // Get process info if available
        let (process_id, process_name) = if let Ok(output) = Command::new("lsof")
            .args(["-i", &format!("{}:{}", local_addr.ip(), local_addr.port())])
            .output()
        {
            let output = String::from_utf8_lossy(&output.stdout);
            output.lines().nth(1).map_or((None, None), |line| {
                // Skip header
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    parts[1]
                        .parse::<u32>()
                        .map_or((None, None), |pid| (Some(pid), Some(parts[0].to_string())))
                } else {
                    (None, None)
                }
            })
        } else {
            (None, None)
        };

        Some(SocketInfo {
            local_addr,
            remote_addr,
            state,
            protocol,
            process_id,
            process_name,
            stats: None,
        })
    }

    fn parse_address(addr: &str) -> Option<SocketAddr> {
        let parts: Vec<&str> = addr.split('.').collect();
        if parts.len() != 2 {
            return None;
        }

        let ip = IpAddr::from_str(parts[0]).ok()?;
        let port = parts[1].parse::<u16>().ok()?;

        Some(SocketAddr::new(ip, port))
    }

    #[allow(dead_code)]
    pub fn get_process_info(pid: u32) -> Option<ProcessInfo> {
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

        Some(ProcessInfo {
            pid,
            name: Some(name),
            cmdline: None,
            uid: None,
            start_time: None,
            memory_usage,
            #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
            cpu_usage: cpu_usage.map(|usage| usage as u64),
            user: Some(user),
        })
    }

    #[allow(dead_code)]
    #[allow(unused_variables)]
    fn create_test_socket() -> std::io::Result<()> {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        Ok(())
    }
}
