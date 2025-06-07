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

    fn get_tcp_stats(pid: u32, inode: u64) -> Option<SocketStats> {
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

        // Read TCP stats from /proc/net/tcp
        if let Ok(file) = File::open("/proc/net/tcp") {
            let reader = BufReader::new(file);
            for line in reader.lines().skip(1) {
                if let Ok(line) = line {
                    if let Some(socket_stats) = parse_tcp_stats_line(&line, inode) {
                        stats = socket_stats;
                        break;
                    }
                }
            }
        }

        // Read additional TCP stats from /proc/<pid>/net/tcp
        if let Ok(file) = File::open(format!("/proc/{}/net/tcp", pid)) {
            let reader = BufReader::new(file);
            for line in reader.lines().skip(1) {
                if let Ok(line) = line {
                    if let Some(socket_stats) = parse_tcp_stats_line(&line, inode) {
                        // Update stats with process-specific information
                        stats.bytes_sent = socket_stats.bytes_sent;
                        stats.bytes_received = socket_stats.bytes_received;
                        stats.packets_sent = socket_stats.packets_sent;
                        stats.packets_received = socket_stats.packets_received;
                        stats.retransmits = socket_stats.retransmits;
                        break;
                    }
                }
            }
        }

        // Read TCP memory stats from /proc/net/sockstat
        if let Ok(file) = File::open("/proc/net/sockstat") {
            let reader = BufReader::new(file);
            for line in reader.lines() {
                if let Ok(line) = line {
                    if line.starts_with("TCP:") {
                        if let Some((send_queue, receive_queue)) = parse_sockstat_line(&line) {
                            stats.send_queue_size = Some(send_queue);
                            stats.receive_queue_size = Some(receive_queue);
                        }
                    }
                }
            }
        }

        Some(stats)
    }

    fn parse_tcp_stats_line(line: &str, target_inode: u64) -> Option<SocketStats> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 17 {
            return None;
        }

        // Extract inode
        let inode = parts[9].parse::<u64>().ok()?;
        if inode != target_inode {
            return None;
        }

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
        };

        // Parse TCP stats
        if let (Ok(send_queue), Ok(receive_queue)) =
            (parts[4].parse::<u32>(), parts[5].parse::<u32>())
        {
            stats.send_queue_size = Some(send_queue);
            stats.receive_queue_size = Some(receive_queue);
        }

        if let (Ok(snd_una), Ok(snd_nxt)) = (parts[10].parse::<u32>(), parts[11].parse::<u32>()) {
            stats.snd_una = Some(snd_una);
            stats.snd_nxt = Some(snd_nxt);
        }

        if let (Ok(rcv_nxt), Ok(rcv_mss)) = (parts[12].parse::<u32>(), parts[13].parse::<u32>()) {
            stats.rcv_nxt = Some(rcv_nxt);
            stats.rcv_mss = Some(rcv_mss);
            stats.snd_mss = Some(rcv_mss); // MSS is same for both directions
        }

        if let (Ok(rtt), Ok(rttvar)) = (parts[14].parse::<u32>(), parts[15].parse::<u32>()) {
            stats.rtt = Some(Duration::from_micros(rtt as u64));
            stats.rtt_variance = Some(Duration::from_micros(rttvar as u64));
        }

        if let Ok(cwnd) = parts[16].parse::<u32>() {
            stats.congestion_window = Some(cwnd);
        }

        Some(stats)
    }

    fn parse_sockstat_line(line: &str) -> Option<(u32, u32)> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            return None;
        }

        let send_queue = parts[2].parse::<u32>().ok()?;
        let receive_queue = parts[3].parse::<u32>().ok()?;

        Some((send_queue, receive_queue))
    }

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
                                // Get TCP stats
                                socket.stats = get_tcp_stats(pid, inode);
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
                if let Some(mut socket) = parse_netstat_line(line) {
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
    // ... rest of the implementation ...
}

#[cfg(target_os = "macos")]
mod macos {
    use super::{
        Protocol, SocketFamily, SocketInfo, SocketOptions, SocketState, SocketStats, SocketType,
    };
    use crate::ProcessInfo;
    use std::net::{IpAddr, SocketAddr};
    use std::process::Command;
    use std::str::FromStr;

    fn get_tcp_stats(pid: u32, local_addr: &SocketAddr) -> Option<SocketStats> {
        // Get detailed TCP stats using netstat
        let output = Command::new("netstat")
            .args([
                "-an", "-p", "tcp", "-v", "-s", // Show statistics
            ])
            .output()
            .ok()?;

        let output = String::from_utf8_lossy(&output.stdout);
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

        // Parse netstat output for TCP statistics
        for line in output.lines() {
            if line.contains("segments sent") {
                if let Some(num) = extract_number(line) {
                    stats.packets_sent = num;
                }
            } else if line.contains("segments received") {
                if let Some(num) = extract_number(line) {
                    stats.packets_received = num;
                }
            } else if line.contains("bytes sent") {
                if let Some(num) = extract_number(line) {
                    stats.bytes_sent = num;
                }
            } else if line.contains("bytes received") {
                if let Some(num) = extract_number(line) {
                    stats.bytes_received = num;
                }
            } else if line.contains("retransmit") {
                if let Some(num) = extract_number(line) {
                    stats.retransmits = num;
                }
            }
        }

        // Get per-socket TCP stats using lsof
        if let Ok(output) = Command::new("lsof")
            .args([
                "-p",
                &pid.to_string(),
                "-i",
                &format!("{}:{}", local_addr.ip(), local_addr.port()),
                "-F",
                "n",
            ])
            .output()
        {
            let output = String::from_utf8_lossy(&output.stdout);
            for line in output.lines() {
                if let Some(flags) = line.strip_prefix("n") {
                    // Parse TCP flags and window information
                    if let Some(window) = extract_window_size(flags) {
                        stats.send_window = Some(window);
                    }
                    if let Some(mss) = extract_mss(flags) {
                        stats.snd_mss = Some(mss);
                        stats.rcv_mss = Some(mss);
                    }
                }
            }
        }

        Some(stats)
    }

    fn extract_number(line: &str) -> Option<u64> {
        line.split_whitespace()
            .find(|s| s.chars().all(|c| c.is_ascii_digit()))
            .and_then(|s| s.parse().ok())
    }

    fn extract_window_size(flags: &str) -> Option<u32> {
        // Look for window size in flags
        flags
            .split_whitespace()
            .find(|s| s.starts_with('w'))
            .and_then(|s| s[1..].parse().ok())
    }

    fn extract_mss(flags: &str) -> Option<u32> {
        // Look for MSS in flags
        flags
            .split_whitespace()
            .find(|s| s.starts_with('m'))
            .and_then(|s| s[1..].parse().ok())
    }

    pub fn get_sockets_info() -> Vec<SocketInfo> {
        let mut sockets = Vec::new();

        // Get TCP sockets using netstat with extended info
        if let Ok(output) = Command::new("netstat")
            .args(["-an", "-p", "tcp", "-v"])
            .output()
        {
            let output = String::from_utf8_lossy(&output.stdout);
            for line in output.lines().skip(2) {
                if let Some(socket) = parse_netstat_line(line, Protocol::Tcp) {
                    sockets.push(socket);
                }
            }
        }

        // Get UDP sockets using netstat with extended info
        if let Ok(output) = Command::new("netstat")
            .args(["-an", "-p", "udp", "-v"])
            .output()
        {
            let output = String::from_utf8_lossy(&output.stdout);
            for line in output.lines().skip(2) {
                if let Some(socket) = parse_netstat_line(line, Protocol::Udp) {
                    sockets.push(socket);
                }
            }
        }

        // Get socket options using lsof
        for socket in &mut sockets {
            if let Some(pid) = socket.process_id {
                if let Ok(output) = Command::new("lsof")
                    .args([
                        "-p",
                        &pid.to_string(),
                        "-i",
                        &format!("{}:{}", socket.local_addr.ip(), socket.local_addr.port()),
                        "-F",
                        "n",
                    ])
                    .output()
                {
                    let output = String::from_utf8_lossy(&output.stdout);
                    socket.socket_options = Some(parse_socket_options(&output));
                }
            }
        }

        // Get TCP stats for each socket
        for socket in &mut sockets {
            if let Some(pid) = socket.process_id {
                if socket.protocol == Protocol::Tcp {
                    socket.stats = get_tcp_stats(pid, &socket.local_addr);
                }
            }
        }

        sockets
    }

    fn parse_socket_options(output: &str) -> SocketOptions {
        let mut options = SocketOptions {
            keep_alive: false,
            reuse_address: false,
            broadcast: false,
            receive_buffer_size: None,
            send_buffer_size: None,
            ttl: None,
            linger: None,
        };

        for line in output.lines() {
            if let Some(flags) = line.strip_prefix("n") {
                options.keep_alive = flags.contains('K');
                options.reuse_address = flags.contains('R');
                options.broadcast = flags.contains('B');
            }
        }

        options
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

        // Determine socket type and family
        let socket_type = match protocol {
            Protocol::Tcp => Some(SocketType::Stream),
            Protocol::Udp => Some(SocketType::Datagram),
            _ => None,
        };

        let socket_family = match local_addr {
            SocketAddr::V4(_) => Some(SocketFamily::Inet),
            SocketAddr::V6(_) => Some(SocketFamily::Inet6),
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
            socket_type,
            socket_family,
            socket_flags: None,
            socket_options: None,
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
