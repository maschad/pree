use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::socket::platform::SocketInfo;
use crate::socket::socket::{Socket, SocketConfig};
use crate::types::{ProcessInfo, Protocol, SocketState};
use crate::Result;

/// Represents a UDP socket
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UdpSocket {
    pub local_addr: SocketAddr,
    pub remote_addr: Option<SocketAddr>,
    pub state: SocketState,
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
    process_info: Option<ProcessInfo>,
}

impl UdpSocket {
    /// Create a new UDP socket instance
    #[must_use]
    pub fn new(
        local_addr: SocketAddr,
        remote_addr: Option<SocketAddr>,
        state: SocketState,
        process_id: Option<u32>,
        process_name: Option<String>,
    ) -> Self {
        let process_info = if let (Some(pid), Some(name)) = (&process_id, &process_name) {
            Some(ProcessInfo {
                pid: *pid,
                name: Some(name.clone()),
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
        Self {
            local_addr,
            remote_addr,
            state,
            process_id,
            process_name,
            process_info,
        }
    }
}

impl SocketConfig for UdpSocket {
    fn find_by_local_addr(addr: SocketAddr) -> Result<Option<Self>> {
        Ok(Socket::list()?
            .into_iter()
            .filter(|s| s.protocol == Protocol::Udp)
            .find(|s| s.local_addr == addr)
            .map(|socket| Self {
                local_addr: socket.local_addr,
                remote_addr: socket.remote_addr,
                state: SocketState::Established,
                process_id: socket.process_id,
                process_name: socket.process_name,
                process_info: None,
            }))
    }

    fn list() -> Result<Vec<Self>> {
        Socket::list()?
            .into_iter()
            .filter(|socket| socket.protocol == Protocol::Udp)
            .map(|socket| {
                let process_info =
                    if let (Some(pid), Some(name)) = (&socket.process_id, &socket.process_name) {
                        Some(ProcessInfo {
                            pid: *pid,
                            name: Some(name.clone()),
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
                Ok(Self {
                    local_addr: socket.local_addr,
                    remote_addr: socket.remote_addr,
                    state: SocketState::Established,
                    process_id: socket.process_id,
                    process_name: socket.process_name,
                    process_info,
                })
            })
            .collect()
    }

    fn list_by_process(pid: u32) -> Result<Vec<Self>> {
        Ok(Self::list()?
            .into_iter()
            .filter(|socket| socket.process_id == Some(pid))
            .collect())
    }

    fn count_active() -> Result<usize> {
        Ok(Self::list()?
            .into_iter()
            .filter(|socket| socket.state == SocketState::Established)
            .count())
    }

    fn is_active(&self) -> bool {
        self.state == SocketState::Established
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }

    fn state(&self) -> SocketState {
        self.state.clone()
    }

    fn process_info(&self) -> Option<&ProcessInfo> {
        self.process_info.as_ref()
    }
}

impl From<UdpSocket> for SocketInfo {
    fn from(socket: UdpSocket) -> Self {
        Self {
            local_addr: socket.local_addr,
            remote_addr: socket
                .remote_addr
                .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
            state: socket.state,
            protocol: Protocol::Udp,
            process_id: socket.process_id,
            process_name: socket.process_name,
            stats: None,
        }
    }
}
