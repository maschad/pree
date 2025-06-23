use crate::socket::platform::{SocketFamily, SocketFlags, SocketInfo, SocketType};
use crate::socket::socket::{Socket, SocketConfig, TcpState};
use crate::types::{ProcessInfo, Protocol, SocketState};
use crate::Result;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Represents a TCP socket
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TcpSocket {
    pub local_addr: SocketAddr,
    pub remote_addr: Option<SocketAddr>,
    pub state: TcpState,
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
    process_info: Option<ProcessInfo>,
}

impl TcpSocket {
    /// Create a new TCP socket instance
    #[must_use]
    pub fn new(
        local_addr: SocketAddr,
        remote_addr: Option<SocketAddr>,
        state: TcpState,
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

impl SocketConfig for TcpSocket {
    fn find_by_local_addr(addr: SocketAddr) -> Result<Option<Self>> {
        Ok(Socket::list()?
            .into_iter()
            .filter(|s| s.protocol == Protocol::Tcp)
            .find(|s| s.local_addr == addr)
            .map(|socket| Self {
                local_addr: socket.local_addr,
                remote_addr: socket.remote_addr,
                state: TcpState::Established,
                process_id: socket.process_id,
                process_name: socket.process_name,
                process_info: None,
            }))
    }

    fn list() -> Result<Vec<Self>> {
        Socket::list()?
            .into_iter()
            .filter(|socket| socket.protocol == Protocol::Tcp)
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
                    state: match socket
                        .state
                        .unwrap_or_else(|| SocketState::Unknown(String::new()))
                    {
                        SocketState::Established => TcpState::Established,
                        SocketState::Listen => TcpState::Listen,
                        _ => TcpState::Other(0),
                    },
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
            .filter(|socket| socket.state == TcpState::Established)
            .count())
    }

    fn is_active(&self) -> bool {
        self.state == TcpState::Established
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }

    fn state(&self) -> SocketState {
        match self.state {
            TcpState::Established => SocketState::Established,
            TcpState::Listen => SocketState::Listen,
            _ => SocketState::Unknown("Unknown TCP state".to_string()),
        }
    }

    fn process_info(&self) -> Option<&ProcessInfo> {
        self.process_info.as_ref()
    }
}

impl From<TcpSocket> for SocketInfo {
    fn from(socket: TcpSocket) -> Self {
        Self {
            local_addr: socket.local_addr,
            remote_addr: socket
                .remote_addr
                .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
            state: socket.state.into(),
            protocol: Protocol::Tcp,
            process_id: socket.process_id,
            process_name: socket.process_name,
            stats: None,
            socket_family: Some(SocketFamily::Inet),
            socket_type: Some(SocketType::Stream),
            socket_flags: Some(SocketFlags {
                non_blocking: false,
                close_on_exec: false,
            }),
            socket_options: None,
        }
    }
}
