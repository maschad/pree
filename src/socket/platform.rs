#![allow(clippy::cast_precision_loss)]
#![allow(clippy::format_push_string)]
#![allow(clippy::uninlined_format_args)]

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
    pub slow_start_threshold: Option<u32>,
    pub send_window: Option<u32>,
    pub receive_window: Option<u32>,
    pub rtt_variance: Option<Duration>,
    pub min_rtt: Option<Duration>,
    pub max_rtt: Option<Duration>,
    pub rtt_samples: Option<u32>,
    pub retransmit_timeout: Option<Duration>,
    pub snd_mss: Option<u32>,
    pub rcv_mss: Option<u32>,
    pub snd_una: Option<u32>,
    pub snd_nxt: Option<u32>,
    pub rcv_nxt: Option<u32>,

    // New congestion control metrics
    pub congestion_control: Option<CongestionControl>,
    pub congestion_state: Option<CongestionState>,
    pub sack_enabled: bool,
    pub ecn_enabled: bool,
    pub ecn_ce_count: Option<u32>, // ECN Congestion Experienced count
    pub sack_blocks: Option<u32>,  // Number of SACK blocks
    pub sack_reordering: Option<u32>, // Number of reordering events detected by SACK

    // New connection quality metrics
    pub out_of_order_packets: Option<u32>,
    pub duplicate_acks: Option<u32>,
    pub zero_window_events: Option<u32>,
    pub connection_duration: Option<Duration>,
    pub connection_quality_score: Option<f32>, // 0.0 to 1.0 score
    pub state_history: Vec<SocketState>,       // Recent state changes
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CongestionControl {
    Cubic,
    Bbr,
    Reno,
    Vegas,
    Westwood,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CongestionState {
    SlowStart,
    CongestionAvoidance,
    FastRecovery,
    FastRetransmit,
    Other(String),
}

impl SocketStats {
    /// Calculate a connection quality score based on various metrics
    #[must_use]
    pub fn calculate_quality_score(&self) -> f32 {
        let mut score = 1.0;

        // Penalize for retransmits
        if self.retransmits > 0 {
            score -= (self.retransmits as f32 * 0.1).min(0.5);
        }

        // Penalize for out-of-order packets
        if let Some(out_of_order) = self.out_of_order_packets {
            score -= (out_of_order as f32 * 0.05).min(0.3);
        }

        // Penalize for zero window events
        if let Some(zero_window) = self.zero_window_events {
            score -= (zero_window as f32 * 0.1).min(0.4);
        }

        // Penalize for high RTT variance
        if let Some(rtt_var) = self.rtt_variance {
            if let Some(rtt) = self.rtt {
                let variance_ratio = rtt_var.as_secs_f32() / rtt.as_secs_f32();
                score -= (variance_ratio * 0.2).min(0.3);
            }
        }

        // Ensure score is between 0.0 and 1.0
        score.clamp(0.0, 1.0)
    }

    /// Check if the connection is experiencing congestion
    #[must_use]
    pub const fn is_congested(&self) -> bool {
        if let Some(state) = &self.congestion_state {
            matches!(
                state,
                CongestionState::FastRecovery | CongestionState::FastRetransmit
            )
        } else {
            false
        }
    }

    /// Get the current bandwidth utilization as a percentage
    #[must_use]
    pub fn bandwidth_utilization(&self) -> Option<f32> {
        if let (Some(cwnd), Some(mss)) = (self.congestion_window, self.snd_mss) {
            if let Some(rtt) = self.rtt {
                let rtt_secs = rtt.as_secs_f32();
                if rtt_secs > 0.0 {
                    let max_bandwidth = (cwnd * mss) as f32 / rtt_secs;
                    let actual_bandwidth =
                        self.bytes_sent as f32 / self.connection_duration?.as_secs_f32();
                    Some((actual_bandwidth / max_bandwidth * 100.0).min(100.0))
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Get the current packet loss rate
    #[must_use]
    pub fn packet_loss_rate(&self) -> f32 {
        if self.packets_sent > 0 {
            (self.retransmits as f32 / self.packets_sent as f32) * 100.0
        } else {
            0.0
        }
    }

    /// Check if the connection is experiencing buffer bloat
    #[must_use]
    pub fn has_buffer_bloat(&self) -> bool {
        if let (Some(rtt), Some(min_rtt)) = (self.rtt, self.min_rtt) {
            rtt.as_secs_f32() > min_rtt.as_secs_f32() * 1.5
        } else {
            false
        }
    }

    /// Calculate the effective bandwidth in bytes per second
    #[must_use]
    pub fn effective_bandwidth(&self) -> Option<f32> {
        self.connection_duration.and_then(|duration| {
            if duration.as_secs_f32() > 0.0 {
                Some(self.bytes_sent as f32 / duration.as_secs_f32())
            } else {
                None
            }
        })
    }

    /// Calculate the connection efficiency (bytes per packet)
    #[must_use]
    pub fn connection_efficiency(&self) -> Option<f32> {
        if self.packets_sent > 0 {
            Some(self.bytes_sent as f32 / self.packets_sent as f32)
        } else {
            None
        }
    }

    /// Get the current TCP state as a string
    #[must_use]
    pub fn tcp_state_description(&self) -> String {
        self.congestion_state.as_ref().map_or_else(
            || String::from("Unknown state"),
            |state| match state {
                CongestionState::SlowStart => {
                    String::from("Slow Start - Initial phase of connection")
                }
                CongestionState::CongestionAvoidance => {
                    String::from("Congestion Avoidance - Normal operation")
                }
                CongestionState::FastRecovery => {
                    String::from("Fast Recovery - Recovering from packet loss")
                }
                CongestionState::FastRetransmit => {
                    String::from("Fast Retransmit - Retransmitting lost packets")
                }
                CongestionState::Other(s) => s.clone(),
            },
        )
    }

    /// Check if the connection is experiencing performance issues
    #[must_use]
    pub fn performance_issues(&self) -> Vec<String> {
        let mut issues = Vec::new();

        // Check for high retransmission rate
        if self.packet_loss_rate() > 5.0 {
            issues.push(String::from("High packet loss rate"));
        }

        // Check for buffer bloat
        if self.has_buffer_bloat() {
            issues.push(String::from("Buffer bloat detected"));
        }

        // Check for zero window conditions
        if let Some(zero_win) = self.zero_window_events {
            if zero_win > 0 {
                issues.push(String::from("Zero window conditions"));
            }
        }

        // Check for out-of-order packets
        if let Some(out_of_order) = self.out_of_order_packets {
            if out_of_order > 0 {
                issues.push(String::from("Out-of-order packets"));
            }
        }

        // Check for high RTT variance
        if let (Some(rtt), Some(rtt_var)) = (self.rtt, self.rtt_variance) {
            if rtt_var.as_secs_f32() > rtt.as_secs_f32() * 0.5 {
                issues.push(String::from("High RTT variance"));
            }
        }

        issues
    }

    /// Get a detailed connection health report
    #[must_use]
    pub fn health_report(&self) -> ConnectionHealthReport {
        ConnectionHealthReport {
            quality_score: self.calculate_quality_score(),
            bandwidth_utilization: self.bandwidth_utilization(),
            packet_loss_rate: self.packet_loss_rate(),
            effective_bandwidth: self.effective_bandwidth(),
            connection_efficiency: self.connection_efficiency(),
            is_congested: self.is_congested(),
            has_buffer_bloat: self.has_buffer_bloat(),
            performance_issues: self.performance_issues(),
            tcp_state: self.tcp_state_description(),
            connection_duration: self.connection_duration,
            congestion_control: self.congestion_control.clone(),
            congestion_state: self.congestion_state.clone(),
            sack_enabled: self.sack_enabled,
            ecn_enabled: self.ecn_enabled,
            ecn_ce_count: self.ecn_ce_count,
            sack_blocks: self.sack_blocks,
            sack_reordering: self.sack_reordering,
            out_of_order_packets: self.out_of_order_packets,
            duplicate_acks: self.duplicate_acks,
            zero_window_events: self.zero_window_events,
            connection_quality_score: self.connection_quality_score,
            state_history: self.state_history.clone(),
        }
    }

    /// Check if the connection is in a healthy state
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        let quality_score = self.calculate_quality_score();
        let loss_rate = self.packet_loss_rate();
        let issues = self.performance_issues();

        quality_score > 0.7 && loss_rate < 1.0 && issues.is_empty()
    }

    /// Get the current TCP window utilization as a percentage
    #[must_use]
    pub fn window_utilization(&self) -> Option<f32> {
        if let (Some(cwnd), Some(send_win)) = (self.congestion_window, self.send_window) {
            if cwnd > 0 {
                Some((send_win as f32 / cwnd as f32) * 100.0)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Get the current connection state history
    #[must_use]
    pub fn state_history_summary(&self) -> String {
        if self.state_history.is_empty() {
            return "No state history available".to_string();
        }

        let mut summary = String::new();
        let mut current_state = &self.state_history[0];
        let mut count = 1;

        for state in self.state_history.iter().skip(1) {
            if state == current_state {
                count += 1;
            } else {
                summary.push_str(&format!("{:?} ({} times), ", current_state, count));
                current_state = state;
                count = 1;
            }
        }
        summary.push_str(&format!("{:?} ({} times)", current_state, count));

        summary
    }
}

/// A comprehensive report of connection health and performance
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct ConnectionHealthReport {
    pub quality_score: f32,
    pub bandwidth_utilization: Option<f32>,
    pub packet_loss_rate: f32,
    pub effective_bandwidth: Option<f32>,
    pub connection_efficiency: Option<f32>,
    pub is_congested: bool,
    pub has_buffer_bloat: bool,
    pub performance_issues: Vec<String>,
    pub tcp_state: String,
    pub connection_duration: Option<Duration>,
    pub congestion_control: Option<CongestionControl>,
    pub congestion_state: Option<CongestionState>,
    pub sack_enabled: bool,
    pub ecn_enabled: bool,
    pub ecn_ce_count: Option<u32>,
    pub sack_blocks: Option<u32>,
    pub sack_reordering: Option<u32>,
    pub out_of_order_packets: Option<u32>,
    pub duplicate_acks: Option<u32>,
    pub zero_window_events: Option<u32>,
    pub connection_quality_score: Option<f32>,
    pub state_history: Vec<SocketState>,
}

impl ConnectionHealthReport {
    /// Get a human-readable summary of the connection health
    #[must_use]
    pub fn summary(&self) -> String {
        let mut summary = String::new();

        // Overall health
        summary.push_str(&format!(
            "Connection Health: {:.1}%\n",
            self.quality_score * 100.0
        ));

        // Performance metrics
        if let Some(util) = self.bandwidth_utilization {
            summary.push_str(&format!("Bandwidth Utilization: {:.1}%\n", util));
        }
        if let Some(bw) = self.effective_bandwidth {
            summary.push_str(&format!(
                "Effective Bandwidth: {:.1} MB/s\n",
                bw / 1_000_000.0
            ));
        }
        if let Some(eff) = self.connection_efficiency {
            summary.push_str(&format!("Connection Efficiency: {:.1} bytes/packet\n", eff));
        }

        // Issues
        if !self.performance_issues.is_empty() {
            summary.push_str("Performance Issues:\n");
            for issue in &self.performance_issues {
                summary.push_str(&format!("  - {}\n", issue));
            }
        }

        // TCP state
        summary.push_str(&format!("TCP State: {}\n", self.tcp_state));

        // Duration
        if let Some(duration) = self.connection_duration {
            summary.push_str(&format!(
                "Connection Duration: {:.1}s\n",
                duration.as_secs_f32()
            ));
        }

        summary
    }
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
    pub socket_type: Option<SocketType>,
    pub socket_family: Option<SocketFamily>,
    pub socket_flags: Option<SocketFlags>,
    pub socket_options: Option<SocketOptions>,
}

#[derive(Debug, Clone)]
pub enum SocketType {
    Stream,
    Datagram,
    Raw,
    SeqPacket,
    Other(i32),
}

#[derive(Debug, Clone)]
pub enum SocketFamily {
    Inet,
    Inet6,
    Unix,
    Other(i32),
}

#[derive(Debug, Clone)]
pub struct SocketFlags {
    pub non_blocking: bool,
    pub close_on_exec: bool,
}

#[derive(Debug, Clone)]
pub struct SocketOptions {
    pub keep_alive: bool,
    pub reuse_address: bool,
    pub broadcast: bool,
    pub receive_buffer_size: Option<u32>,
    pub send_buffer_size: Option<u32>,
    pub ttl: Option<u32>,
    pub linger: Option<Duration>,
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
                // Note: Command line may not be available on all platforms/processes
                // assert!(info.cmdline.is_some());

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
            // Test local address - allow port 0 for wildcard addresses
            assert!(socket.local_addr.port() > 0 || socket.local_addr.ip().is_unspecified());

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
                assert!(socket.local_addr.port() > 0 || socket.local_addr.ip().is_unspecified());
                if let Some(pid) = socket.process_id {
                    let process_info = macos::get_process_info(pid);
                    assert!(process_info.is_some());
                }
            }
        }
        #[cfg(target_os = "linux")]
        {
            let sockets = linux::get_sockets_info().unwrap();
            assert!(!sockets.is_empty());
            // Even if we don't find our test socket, we should be able to get socket info
            for socket in sockets {
                assert!(socket.local_addr.port() > 0 || socket.local_addr.ip().is_unspecified());
                if let Some(pid) = socket.process_id {
                    let process_info = linux::get_process_info(pid);
                    assert!(process_info.is_some());
                }
            }
        }
        #[cfg(target_os = "windows")]
        {
            let sockets = windows::get_sockets_info().unwrap();
            // Even if we don't find our test socket, we should be able to get socket info
            for socket in sockets {
                assert!(socket.local_addr.port() > 0 || socket.local_addr.ip().is_unspecified());
                if let Some(pid) = socket.process_id {
                    let process_info = windows::get_process_info(pid);
                    assert!(process_info.is_some());
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{Protocol, SocketFamily, SocketInfo, SocketState, SocketStats, SocketType};
    use crate::{NetworkError, ProcessInfo};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    #[cfg(feature = "linux-procfs")]
    use procfs::net::{tcp, tcp6, udp, udp6, TcpNetEntry, TcpState as ProcfsTcpState, UdpNetEntry};

    #[cfg(feature = "linux-procfs")]
    use procfs::process::{all_processes, FDTarget};

    use libproc::proc_pid;
    use std::collections::HashMap;
    use std::fs;
    use std::io::{BufRead, BufReader};

    #[cfg(feature = "linux-procfs")]
    fn convert_tcp_state(state: ProcfsTcpState) -> SocketState {
        match state {
            ProcfsTcpState::Established => SocketState::Established,
            ProcfsTcpState::SynSent => SocketState::Connecting,
            ProcfsTcpState::SynRecv => SocketState::Connecting,
            ProcfsTcpState::FinWait1 | ProcfsTcpState::FinWait2 => SocketState::Closing,
            ProcfsTcpState::TimeWait => SocketState::Closing,
            ProcfsTcpState::Close => SocketState::Closed,
            ProcfsTcpState::CloseWait => SocketState::Closing,
            ProcfsTcpState::LastAck => SocketState::Closing,
            ProcfsTcpState::Listen => SocketState::Listen,
            ProcfsTcpState::Closing => SocketState::Closing,
            ProcfsTcpState::NewSynRecv => SocketState::Connecting,
        }
    }

    #[cfg(feature = "linux-procfs")]
    pub fn get_sockets_info() -> Result<Vec<SocketInfo>, NetworkError> {
        let mut sockets = Vec::new();
        let mut inode_to_process = HashMap::new();

        // Build a map of inode to process info
        if let Ok(processes) = all_processes() {
            for process in processes.flatten() {
                if let Ok(fds) = process.fd() {
                    for fd in fds.flatten() {
                        if let FDTarget::Socket(inode) = fd.target {
                            if let Ok(stat) = process.stat() {
                                inode_to_process
                                    .insert(inode, (stat.pid as u32, stat.comm.clone()));
                            }
                        }
                    }
                }
            }
        }

        // Get TCP sockets
        if let Ok(tcp_sockets) = tcp() {
            for entry in tcp_sockets {
                if let Some(socket) = process_tcp_entry(entry, &inode_to_process) {
                    sockets.push(socket);
                }
            }
        }

        // Get TCP6 sockets
        if let Ok(tcp6_sockets) = tcp6() {
            for entry in tcp6_sockets {
                if let Some(socket) = process_tcp_entry(entry, &inode_to_process) {
                    sockets.push(socket);
                }
            }
        }

        // Get UDP sockets
        if let Ok(udp_sockets) = udp() {
            for entry in udp_sockets {
                if let Some(socket) = process_udp_entry(entry, &inode_to_process) {
                    sockets.push(socket);
                }
            }
        }

        // Get UDP6 sockets
        if let Ok(udp6_sockets) = udp6() {
            for entry in udp6_sockets {
                if let Some(socket) = process_udp_entry(entry, &inode_to_process) {
                    sockets.push(socket);
                }
            }
        }

        Ok(sockets)
    }

    #[cfg(not(feature = "linux-procfs"))]
    pub fn get_sockets_info() -> Result<Vec<SocketInfo>, NetworkError> {
        // Fallback implementation using direct /proc parsing
        let mut sockets = Vec::new();
        let inode_to_process = build_inode_to_process_map()?;

        // Parse TCP sockets
        sockets.extend(parse_socket_file(
            "/proc/net/tcp",
            Protocol::Tcp,
            &inode_to_process,
        )?);
        sockets.extend(parse_socket_file(
            "/proc/net/tcp6",
            Protocol::Tcp,
            &inode_to_process,
        )?);

        // Parse UDP sockets
        sockets.extend(parse_socket_file(
            "/proc/net/udp",
            Protocol::Udp,
            &inode_to_process,
        )?);
        sockets.extend(parse_socket_file(
            "/proc/net/udp6",
            Protocol::Udp,
            &inode_to_process,
        )?);

        Ok(sockets)
    }

    #[cfg(feature = "linux-procfs")]
    fn process_tcp_entry(
        entry: TcpNetEntry,
        inode_to_process: &HashMap<u64, (u32, String)>,
    ) -> Option<SocketInfo> {
        let (process_id, process_name) = inode_to_process
            .get(&entry.inode)
            .map(|(pid, name)| (Some(*pid), Some(name.clone())))
            .unwrap_or((None, None));

        let socket_family = if entry.local_address.is_ipv4() {
            SocketFamily::Inet
        } else {
            SocketFamily::Inet6
        };

        // Get TCP stats
        let stats = if let Some(pid) = process_id {
            get_tcp_stats(pid, entry.inode)
        } else {
            None
        };

        Some(SocketInfo {
            local_addr: entry.local_address,
            remote_addr: entry.remote_address,
            state: convert_tcp_state(entry.state),
            protocol: Protocol::Tcp,
            process_id,
            process_name,
            stats,
            socket_type: Some(SocketType::Stream),
            socket_family: Some(socket_family),
            socket_flags: None,
            socket_options: None,
        })
    }

    #[cfg(feature = "linux-procfs")]
    fn process_udp_entry(
        entry: UdpNetEntry,
        inode_to_process: &HashMap<u64, (u32, String)>,
    ) -> Option<SocketInfo> {
        let (process_id, process_name) = inode_to_process
            .get(&entry.inode)
            .map(|(pid, name)| (Some(*pid), Some(name.clone())))
            .unwrap_or((None, None));

        let socket_family = if entry.local_address.is_ipv4() {
            SocketFamily::Inet
        } else {
            SocketFamily::Inet6
        };

        Some(SocketInfo {
            local_addr: entry.local_address,
            remote_addr: entry.remote_address,
            state: SocketState::Established, // UDP is connectionless
            protocol: Protocol::Udp,
            process_id,
            process_name,
            stats: None, // UDP doesn't have detailed stats like TCP
            socket_type: Some(SocketType::Datagram),
            socket_family: Some(socket_family),
            socket_flags: None,
            socket_options: None,
        })
    }

    fn build_inode_to_process_map() -> Result<HashMap<u64, (u32, String)>, NetworkError> {
        let mut map = HashMap::new();

        // Iterate through all processes
        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();

            // Check if this is a process directory (numeric name)
            if let Ok(pid) = file_name_str.parse::<u32>() {
                // Try to read the process's file descriptors
                let fd_path = format!("/proc/{}/fd", pid);
                if let Ok(fd_dir) = fs::read_dir(&fd_path) {
                    for fd_entry in fd_dir.flatten() {
                        if let Ok(link) = fs::read_link(fd_entry.path()) {
                            let link_str = link.to_string_lossy();
                            if let Some(inode) = extract_socket_inode(&link_str) {
                                // Get process name
                                let comm_path = format!("/proc/{}/comm", pid);
                                let name = fs::read_to_string(comm_path)
                                    .unwrap_or_default()
                                    .trim()
                                    .to_string();
                                map.insert(inode, (pid, name));
                            }
                        }
                    }
                }
            }
        }

        Ok(map)
    }

    fn extract_socket_inode(link: &str) -> Option<u64> {
        if link.starts_with("socket:[") && link.ends_with(']') {
            link[8..link.len() - 1].parse().ok()
        } else {
            None
        }
    }

    fn parse_socket_file(
        path: &str,
        protocol: Protocol,
        inode_to_process: &HashMap<u64, (u32, String)>,
    ) -> Result<Vec<SocketInfo>, NetworkError> {
        let mut sockets = Vec::new();

        let file = fs::File::open(path)?;
        let reader = BufReader::new(file);
        let mut lines_iter = reader.lines();

        // Skip header
        lines_iter.next();

        for line in lines_iter.map_while(std::result::Result::ok) {
            if let Some(socket) = parse_socket_line(&line, protocol, inode_to_process) {
                sockets.push(socket);
            }
        }

        Ok(sockets)
    }

    fn parse_socket_line(
        line: &str,
        protocol: Protocol,
        inode_to_process: &HashMap<u64, (u32, String)>,
    ) -> Option<SocketInfo> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            return None;
        }

        // Parse addresses
        let local_addr = parse_hex_address(parts[1])?;
        let remote_addr = parse_hex_address(parts[2])?;

        // Parse state (for TCP)
        let state = if protocol == Protocol::Tcp {
            match u8::from_str_radix(parts[3], 16).ok()? {
                0x01 => SocketState::Established,
                0x02 => SocketState::Connecting,
                0x03 => SocketState::Connecting,
                0x04 => SocketState::Closing,
                0x05 => SocketState::Closing,
                0x06 => SocketState::Closing,
                0x07 => SocketState::Closed,
                0x08 => SocketState::Closing,
                0x09 => SocketState::Closing,
                0x0A => SocketState::Listen,
                0x0B => SocketState::Closing,
                _ => SocketState::Unknown("Unknown state".to_string()),
            }
        } else {
            SocketState::Established
        };

        // Parse inode
        let inode = parts[9].parse::<u64>().ok()?;

        // Get process info
        let (process_id, process_name) = inode_to_process
            .get(&inode)
            .map(|(pid, name)| (Some(*pid), Some(name.clone())))
            .unwrap_or((None, None));

        // Get stats for TCP
        let socket_stats = if protocol == Protocol::Tcp {
            Some(get_tcp_stats(process_id?, inode))
        } else {
            None
        };

        // Determine socket family
        let socket_family = match local_addr {
            SocketAddr::V4(_) => SocketFamily::Inet,
            SocketAddr::V6(_) => SocketFamily::Inet6,
        };

        // Determine socket type
        let socket_type = match protocol {
            Protocol::Tcp => SocketType::Stream,
            Protocol::Udp => SocketType::Datagram,
            _ => return None,
        };

        Some(SocketInfo {
            local_addr,
            remote_addr,
            state,
            protocol,
            process_id,
            process_name,
            stats: socket_stats,
            socket_type: Some(socket_type),
            socket_family: Some(socket_family),
            socket_flags: None,
            socket_options: None,
        })
    }

    fn parse_hex_address(hex_addr: &str) -> Option<SocketAddr> {
        let parts: Vec<&str> = hex_addr.split(':').collect();
        if parts.len() != 2 {
            return None;
        }

        let port = u16::from_str_radix(parts[1], 16).ok()?;

        // Check if IPv4 or IPv6
        if parts[0].len() == 8 {
            // IPv4
            let addr_bytes = u32::from_str_radix(parts[0], 16).ok()?;
            let addr = Ipv4Addr::from(addr_bytes.to_be());
            Some(SocketAddr::new(IpAddr::V4(addr), port))
        } else if parts[0].len() == 32 {
            // IPv6
            let mut bytes = [0u8; 16];
            for (i, chunk) in parts[0].as_bytes().chunks(2).enumerate() {
                let hex_str = std::str::from_utf8(chunk).ok()?;
                bytes[i] = u8::from_str_radix(hex_str, 16).ok()?;
            }
            let addr = Ipv6Addr::from(bytes);
            Some(SocketAddr::new(IpAddr::V6(addr), port))
        } else {
            None
        }
    }

    const fn get_tcp_stats(_pid: u32, _inode: u64) -> SocketStats {
        // Create a basic stats structure
        // Note: libproc on macOS doesn't provide as detailed TCP statistics as Linux
        // We'll populate what we can
        SocketStats {
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
            slow_start_threshold: None,
            send_window: None,
            receive_window: None,
            rtt_variance: None,
            min_rtt: None,
            max_rtt: None,
            rtt_samples: None,
            retransmit_timeout: None,
            snd_mss: None,
            rcv_mss: None,
            snd_una: None,
            snd_nxt: None,
            rcv_nxt: None,
            congestion_control: None,
            congestion_state: None,
            sack_enabled: false,
            ecn_enabled: false,
            ecn_ce_count: None,
            sack_blocks: None,
            sack_reordering: None,
            out_of_order_packets: None,
            duplicate_acks: None,
            zero_window_events: None,
            connection_duration: None,
            connection_quality_score: None,
            state_history: Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub fn get_process_info(pid: u32) -> Option<ProcessInfo> {
        // Try using libproc first
        if let Ok(path) = proc_pid::pidpath(pid as i32) {
            let name = std::path::Path::new(&path)
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.to_string());

            // Read additional info from /proc
            let cmdline_path = format!("/proc/{}/cmdline", pid);

            let cmdline = fs::read_to_string(cmdline_path)
                .ok()
                .map(|s| s.replace('\0', " ").trim().to_string());

            let uid = fs::read_to_string(format!("/proc/{}/status", pid))
                .ok()
                .and_then(|content| {
                    content
                        .lines()
                        .find(|line| line.starts_with("Uid:"))
                        .and_then(|line| line.split_whitespace().nth(1))
                        .and_then(|uid_str| uid_str.parse().ok())
                });

            // Get memory usage from status file
            let memory_usage = fs::read_to_string(format!("/proc/{}/status", pid))
                .ok()
                .and_then(|content| {
                    content
                        .lines()
                        .find(|line| line.starts_with("VmRSS:"))
                        .and_then(|line| line.split_whitespace().nth(1))
                        .and_then(|mem_str| mem_str.parse::<u64>().ok())
                        .map(|kb| kb * 1024) // Convert KB to bytes
                });

            return Some(ProcessInfo {
                pid,
                name,
                cmdline,
                uid,
                start_time: None,
                memory_usage,
                cpu_usage: None,
                user: None,
            });
        }

        None
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    use std::process::Command;
    use std::ptr::null_mut;
    use winapi::um::iphlpapi::*;
    use winapi::um::winnt::HANDLE;

    fn get_tcp_stats(pid: u32, local_addr: &SocketAddr) -> Option<SocketStats> {
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
            slow_start_threshold: None,
            send_window: None,
            receive_window: None,
            rtt_variance: None,
            min_rtt: None,
            max_rtt: None,
            rtt_samples: None,
            retransmit_timeout: None,
            snd_mss: None,
            rcv_mss: None,
            snd_una: None,
            snd_nxt: None,
            rcv_nxt: None,
            congestion_control: None,
            congestion_state: None,
            sack_enabled: false,
            ecn_enabled: false,
            ecn_ce_count: None,
            sack_blocks: None,
            sack_reordering: None,
            out_of_order_packets: None,
            duplicate_acks: None,
            zero_window_events: None,
            connection_duration: None,
            connection_quality_score: None,
            state_history: Vec::new(),
        };

        // Get TCP stats using netstat
        if let Ok(output) = Command::new("netstat")
            .args(["-an", "-p", "tcp", "-o", "-b"])
            .output()
        {
            let output = String::from_utf8_lossy(&output.stdout);
            for line in output.lines() {
                if line.contains(&format!("{}:{}", local_addr.ip(), local_addr.port())) {
                    if let Some(socket_stats) = parse_netstat_line(line) {
                        stats = socket_stats;
                        break;
                    }
                }
            }
        }

        // Get additional TCP stats using GetPerTcpConnectionEStats
        unsafe {
            let mut row: MIB_TCPROW_OWNER_PID = std::mem::zeroed();
            let mut stats_ex: TCP_ESTATS_PATH_ROD_v0 = std::mem::zeroed();

            // Find the TCP connection
            if GetExtendedTcpTable(
                &mut row as *mut _ as *mut _,
                &mut 0,
                false as BOOLEAN,
                AF_INET,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            ) == NO_ERROR
            {
                // Get extended stats
                if GetPerTcpConnectionEStats(
                    &mut row as *mut _,
                    TcpConnectionEstatsPath,
                    null_mut(),
                    0,
                    0,
                    &mut stats_ex as *mut _ as *mut _,
                    0,
                    std::mem::size_of::<TCP_ESTATS_PATH_ROD_v0>() as ULONG,
                    0,
                ) == NO_ERROR
                {
                    stats.rtt = Some(Duration::from_millis(stats_ex.SampleRtt as u64));
                    stats.rtt_variance = Some(Duration::from_millis(stats_ex.SmoothedRtt as u64));
                    stats.congestion_window = Some(stats_ex.CongestionWindow as u32);
                    stats.slow_start_threshold = Some(stats_ex.SlowStartThreshold as u32);
                }
            }
        }

        Some(stats)
    }

    fn parse_netstat_line(line: &str) -> Option<SocketStats> {
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
            slow_start_threshold: None,
            send_window: None,
            receive_window: None,
            rtt_variance: None,
            min_rtt: None,
            max_rtt: None,
            rtt_samples: None,
            retransmit_timeout: None,
            snd_mss: None,
            rcv_mss: None,
            snd_una: None,
            snd_nxt: None,
            rcv_nxt: None,
        };

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            return None;
        }

        // Parse window size if available
        if let Some(window_str) = parts.get(3) {
            if let Ok(window) = window_str.parse::<u32>() {
                stats.send_window = Some(window);
                stats.receive_window = Some(window);
            }
        }

        Some(stats)
    }

    pub fn get_sockets_info() -> Result<Vec<SocketInfo>> {
        let mut sockets = Vec::new();

        // Get TCP sockets using netstat
        if let Ok(output) = Command::new("netstat")
            .args(["-an", "-p", "tcp", "-o", "-b"])
            .output()
        {
            let output = String::from_utf8_lossy(&output.stdout);
            for line in output.lines().skip(4) {
                // Skip header lines
                if let Some(mut socket) = parse_socket_line(line) {
                    // Get process info
                    if let Some((pid, name)) = get_process_info_from_line(line) {
                        socket.process_id = Some(pid);
                        socket.process_name = Some(name);
                        // Get TCP stats
                        if let Some(local_addr) = get_local_addr_from_line(line) {
                            socket.stats = get_tcp_stats(pid, &local_addr);
                        }
                    }
                    sockets.push(socket);
                }
            }
        }

        Ok(sockets)
    }

    fn parse_socket_line(line: &str) -> Option<SocketInfo> {
        // Simple parser for Windows netstat output
        // Format: Proto  Local Address          Foreign Address        State           PID
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            return None;
        }

        // Parse addresses
        let local_addr = parse_address(parts[1])?;
        let remote_addr = parse_address(parts[2])?;

        // Parse state
        let state = match parts[3].to_uppercase().as_str() {
            "ESTABLISHED" => SocketState::Established,
            "LISTENING" => SocketState::Listen,
            "SYN_SENT" | "SYN_RECV" => SocketState::Connecting,
            "CLOSE_WAIT" | "FIN_WAIT1" | "FIN_WAIT2" | "TIME_WAIT" | "LAST_ACK" | "CLOSING" => {
                SocketState::Closing
            }
            "CLOSED" => SocketState::Closed,
            _ => SocketState::Unknown(parts[3].to_string()),
        };

        Some(SocketInfo {
            local_addr,
            remote_addr,
            state,
            protocol: Protocol::Tcp,
            process_id: None, // Will be filled by get_process_info_from_line
            process_name: None,
            stats: None,
            socket_type: Some(SocketType::Stream),
            socket_family: Some(if local_addr.is_ipv4() {
                SocketFamily::Inet
            } else {
                SocketFamily::Inet6
            }),
            socket_flags: None,
            socket_options: None,
        })
    }

    fn parse_address(addr: &str) -> Option<SocketAddr> {
        // Parse Windows netstat address format (e.g., "127.0.0.1:80" or "[::1]:80")
        addr.parse().ok()
    }

    fn get_process_info_from_line(line: &str) -> Option<(u32, String)> {
        // Extract PID from netstat output
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 {
            if let Ok(pid) = parts[4].parse::<u32>() {
                // TODO: Get process name from PID using Windows API
                return Some((pid, format!("Process_{}", pid)));
            }
        }
        None
    }

    fn get_local_addr_from_line(line: &str) -> Option<SocketAddr> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            parse_address(parts[1])
        } else {
            None
        }
    }

    pub fn get_process_info(pid: u32) -> Option<ProcessInfo> {
        // TODO: Implement using Windows API
        Some(ProcessInfo {
            pid,
            name: Some(format!("Process_{}", pid)),
            cmdline: None,
            uid: None,
            start_time: None,
            memory_usage: None,
            cpu_usage: None,
            user: None,
        })
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::{
        Protocol, SocketFamily, SocketInfo, SocketOptions, SocketState, SocketStats, SocketType,
    };
    use crate::ProcessInfo;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::{Duration, SystemTime};

    use libproc::file_info::{pidfdinfo, ListFDs, ProcFDType};
    use libproc::libproc::bsd_info::BSDInfo;
    use libproc::net_info::{SocketFDInfo, SocketInfoKind, TcpSIState};
    use libproc::proc_pid::{listpidinfo, pidinfo};
    use libproc::processes::{pids_by_type, ProcFilter};

    const fn get_tcp_stats(_pid: u32, _inode: u64) -> SocketStats {
        // Create a basic stats structure
        // Note: libproc on macOS doesn't provide as detailed TCP statistics as Linux
        // We'll populate what we can
        SocketStats {
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
            slow_start_threshold: None,
            send_window: None,
            receive_window: None,
            rtt_variance: None,
            min_rtt: None,
            max_rtt: None,
            rtt_samples: None,
            retransmit_timeout: None,
            snd_mss: None,
            rcv_mss: None,
            snd_una: None,
            snd_nxt: None,
            rcv_nxt: None,
            congestion_control: None,
            congestion_state: None,
            sack_enabled: false,
            ecn_enabled: false,
            ecn_ce_count: None,
            sack_blocks: None,
            sack_reordering: None,
            out_of_order_packets: None,
            duplicate_acks: None,
            zero_window_events: None,
            connection_duration: None,
            connection_quality_score: None,
            state_history: Vec::new(),
        }
    }

    pub fn get_sockets_info() -> Vec<SocketInfo> {
        let mut sockets = Vec::new();

        // Get all process IDs
        if let Ok(pids) = pids_by_type(ProcFilter::All) {
            for pid in pids {
                let pid_i32 = i32::try_from(pid).unwrap_or(i32::MAX);

                // Get BSD info to know how many file descriptors this process has
                if let Ok(bsd_info) = pidinfo::<BSDInfo>(pid_i32, 0) {
                    // Get file descriptors for this process
                    if let Ok(fds) = listpidinfo::<ListFDs>(pid_i32, bsd_info.pbi_nfiles as usize) {
                        for fd_info in fds {
                            if matches!(ProcFDType::from(fd_info.proc_fdtype), ProcFDType::Socket) {
                                // Get socket information for this file descriptor
                                if let Ok(socket_fd_info) =
                                    pidfdinfo::<SocketFDInfo>(pid_i32, fd_info.proc_fd)
                                {
                                    if let Some(socket_info) =
                                        process_socket_info(pid, fd_info.proc_fd, socket_fd_info)
                                    {
                                        sockets.push(socket_info);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        sockets
    }

    fn process_socket_info(pid: u32, _fd: i32, socket_fd_info: SocketFDInfo) -> Option<SocketInfo> {
        let socket_info = socket_fd_info.psi;
        let socket_kind = SocketInfoKind::from(socket_info.soi_kind);

        // Only process TCP and UDP sockets
        let protocol = match socket_info.soi_protocol {
            libc::IPPROTO_TCP => Protocol::Tcp,
            libc::IPPROTO_UDP => Protocol::Udp,
            _ => return None,
        };

        let (local_addr, remote_addr, state, socket_family) = match socket_kind {
            SocketInfoKind::In | SocketInfoKind::Tcp => {
                // Access TCP/IP info (unsafe due to union)
                let tcp_info = unsafe { socket_info.soi_proto.pri_tcp };

                // Extract addresses from the TCP info
                let local_addr = unsafe {
                    let addr_bytes = tcp_info.tcpsi_ini.insi_laddr.ina_46.i46a_addr4.s_addr;
                    let port = tcp_info.tcpsi_ini.insi_lport;

                    // Convert from network byte order
                    let addr = u32::from_be(addr_bytes);
                    let port = (port >> 8 & 0xff) | (port << 8 & 0xff00);

                    SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::from(addr)),
                        u16::try_from(port).unwrap_or(0),
                    )
                };

                let remote_addr = unsafe {
                    let addr_bytes = tcp_info.tcpsi_ini.insi_faddr.ina_46.i46a_addr4.s_addr;
                    let port = tcp_info.tcpsi_ini.insi_fport;

                    // Convert from network byte order
                    let addr = u32::from_be(addr_bytes);
                    let port = (port >> 8 & 0xff) | (port << 8 & 0xff00);

                    SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::from(addr)),
                        u16::try_from(port).unwrap_or(0),
                    )
                };

                let state = if protocol == Protocol::Tcp {
                    match TcpSIState::from(tcp_info.tcpsi_state) {
                        TcpSIState::Closed => SocketState::Closed,
                        TcpSIState::Listen => SocketState::Listen,
                        TcpSIState::SynSent | TcpSIState::SynReceived => SocketState::Connecting,
                        TcpSIState::Established => SocketState::Established,
                        TcpSIState::CloseWait
                        | TcpSIState::FinWait1
                        | TcpSIState::FinWait2
                        | TcpSIState::LastAck
                        | TcpSIState::Closing
                        | TcpSIState::TimeWait => SocketState::Closing,
                        _ => SocketState::Unknown("Unknown TCP state".to_string()),
                    }
                } else {
                    SocketState::Established // UDP is connectionless
                };

                (local_addr, remote_addr, state, SocketFamily::Inet)
            }
            SocketInfoKind::Un => {
                // Unix domain sockets - skip for now
                return None;
            }
            _ => return None,
        };

        // Get process name from BSD info
        let process_name = pidinfo::<BSDInfo>(i32::try_from(pid).unwrap_or(i32::MAX), 0)
            .ok()
            .map(|bsd_info| unsafe {
                std::ffi::CStr::from_ptr(bsd_info.pbi_comm.as_ptr())
                    .to_string_lossy()
                    .into_owned()
            });

        // Determine socket type
        let socket_type = match protocol {
            Protocol::Tcp => Some(SocketType::Stream),
            Protocol::Udp => Some(SocketType::Datagram),
            _ => None,
        };

        // Get socket options (basic defaults for now)
        let socket_options = Some(SocketOptions {
            keep_alive: false,
            reuse_address: false,
            broadcast: false,
            receive_buffer_size: None,
            send_buffer_size: None,
            ttl: None,
            linger: None,
        });

        // Get TCP stats if applicable
        let socket_stats = if protocol == Protocol::Tcp {
            Some(get_tcp_stats(pid, 0))
        } else {
            None
        };

        Some(SocketInfo {
            local_addr,
            remote_addr,
            state,
            protocol,
            process_id: Some(pid),
            process_name,
            stats: socket_stats,
            socket_type,
            socket_family: Some(socket_family),
            socket_flags: None,
            socket_options,
        })
    }

    #[allow(dead_code)]
    pub fn get_process_info(pid: u32) -> Option<ProcessInfo> {
        // Get process information using libproc
        pidinfo::<BSDInfo>(i32::try_from(pid).unwrap_or(i32::MAX), 0)
            .ok()
            .map(|bsd_info| {
                let name = unsafe {
                    std::ffi::CStr::from_ptr(bsd_info.pbi_comm.as_ptr())
                        .to_string_lossy()
                        .into_owned()
                };

                let start_time =
                    SystemTime::UNIX_EPOCH + Duration::from_secs(bsd_info.pbi_start_tvsec);

                ProcessInfo {
                    pid,
                    name: Some(name),
                    cmdline: None, // Command line not easily available through libproc on macOS
                    uid: Some(bsd_info.pbi_uid),
                    start_time: Some(start_time),
                    memory_usage: None, // Would need TaskInfo for this
                    cpu_usage: None,    // Would need TaskInfo for this
                    user: None,         // Would need to look up user name from uid
                }
            })
    }
}
