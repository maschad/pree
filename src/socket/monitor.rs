use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::socket::platform::SocketInfo;
use crate::socket::socket::Socket;
use crate::types::{Protocol, SocketState};
use crate::Result;

/// Events that can occur for a socket
#[derive(Debug, Clone)]
pub enum SocketEvent {
    /// A new socket was opened
    Opened(SocketInfo),
    /// An existing socket was closed
    Closed(SocketInfo),
    /// A socket's state changed
    StateChanged(SocketInfo),
}

/// Callback function type for socket events
pub type SocketCallback = Box<dyn Fn(SocketEvent) + Send + 'static>;

/// Monitors socket changes in real-time
pub struct SocketMonitor {
    tx: Sender<SocketEvent>,
    rx: Arc<Mutex<Receiver<SocketEvent>>>,
    callbacks: Arc<Mutex<Vec<SocketCallback>>>,
    interval: Duration,
    running: bool,
}

impl SocketMonitor {
    /// Create a new socket monitor with default settings
    pub fn new() -> Self {
        let (tx, rx) = channel();
        Self {
            tx,
            rx: Arc::new(Mutex::new(rx)),
            callbacks: Arc::new(Mutex::new(Vec::new())),
            interval: Duration::from_secs(1),
            running: false,
        }
    }

    /// Set the polling interval for socket changes
    pub fn interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Register a callback for socket events
    pub fn on_socket_change<F>(&mut self, callback: F) -> Result<()>
    where
        F: Fn(SocketEvent) + Send + 'static,
    {
        if let Ok(mut callbacks) = self.callbacks.lock() {
            callbacks.push(Box::new(callback));
        }
        Ok(())
    }

    /// Start monitoring socket changes
    #[allow(clippy::too_many_lines)]
    pub fn start(&mut self) -> Result<()> {
        if self.running {
            return Ok(());
        }

        self.running = true;
        let tx = self.tx.clone();
        let interval = self.interval;
        let rx = Arc::clone(&self.rx);

        // Start socket monitoring thread
        thread::spawn(move || {
            let mut previous_sockets: HashSet<Socket> = HashSet::new();

            loop {
                if let Ok(sockets) = Socket::list() {
                    let current_sockets: HashSet<_> = sockets.into_iter().collect();

                    // Check for new sockets
                    for socket in &current_sockets {
                        if !previous_sockets.contains(socket) {
                            let info = SocketInfo {
                                local_addr: socket.local_addr,
                                remote_addr: socket.remote_addr.unwrap_or_else(|| {
                                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                                }),
                                state: socket.state.as_ref().map_or_else(
                                    || SocketState::Unknown("No state".to_string()),
                                    |s| match s {
                                        SocketState::Established => SocketState::Established,
                                        SocketState::Listen => SocketState::Listen,
                                        _ => SocketState::Unknown("Unknown TCP state".to_string()),
                                    },
                                ),
                                protocol: match socket.protocol {
                                    Protocol::Tcp => Protocol::Tcp,
                                    Protocol::Udp => Protocol::Udp,
                                    Protocol::Icmp => Protocol::Tcp,
                                    Protocol::Raw => Protocol::Tcp,
                                    Protocol::Other(_) => Protocol::Tcp,
                                },
                                process_id: socket.process_id,
                                process_name: socket.process_name.clone(),
                                stats: None,
                            };
                            let _ = tx.send(SocketEvent::Opened(info));
                        }
                    }

                    // Check for closed sockets
                    for socket in &previous_sockets {
                        if !current_sockets.contains(socket) {
                            let info = SocketInfo {
                                local_addr: socket.local_addr,
                                remote_addr: socket.remote_addr.unwrap_or_else(|| {
                                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                                }),
                                state: socket.state.as_ref().map_or_else(
                                    || SocketState::Unknown("No state".to_string()),
                                    |s| match s {
                                        SocketState::Established => SocketState::Established,
                                        SocketState::Listen => SocketState::Listen,
                                        _ => SocketState::Unknown("Unknown TCP state".to_string()),
                                    },
                                ),
                                protocol: match socket.protocol {
                                    Protocol::Tcp => Protocol::Tcp,
                                    Protocol::Udp => Protocol::Udp,
                                    Protocol::Icmp => Protocol::Tcp,
                                    Protocol::Raw => Protocol::Tcp,
                                    Protocol::Other(_) => Protocol::Tcp,
                                },
                                process_id: socket.process_id,
                                process_name: socket.process_name.clone(),
                                stats: None,
                            };
                            let _ = tx.send(SocketEvent::Closed(info));
                        }
                    }

                    // Check for state changes
                    for socket in &current_sockets {
                        if let Some(prev_socket) = previous_sockets.get(socket) {
                            if socket.state != prev_socket.state {
                                let info = SocketInfo {
                                    local_addr: socket.local_addr,
                                    remote_addr: socket.remote_addr.unwrap_or_else(|| {
                                        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                                    }),
                                    state: socket.state.as_ref().map_or_else(
                                        || SocketState::Unknown("No state".to_string()),
                                        |s| match s {
                                            SocketState::Established => SocketState::Established,
                                            SocketState::Listen => SocketState::Listen,
                                            _ => SocketState::Unknown(
                                                "Unknown TCP state".to_string(),
                                            ),
                                        },
                                    ),
                                    protocol: match socket.protocol {
                                        Protocol::Tcp => Protocol::Tcp,
                                        Protocol::Udp => Protocol::Udp,
                                        Protocol::Icmp => Protocol::Tcp,
                                        Protocol::Raw => Protocol::Tcp,
                                        Protocol::Other(_) => Protocol::Tcp,
                                    },
                                    process_id: socket.process_id,
                                    process_name: socket.process_name.clone(),
                                    stats: None,
                                };
                                let _ = tx.send(SocketEvent::StateChanged(info));
                            }
                        }
                    }

                    previous_sockets = current_sockets;
                }

                thread::sleep(interval);
            }
        });

        // Start event processing thread
        let callbacks = Arc::clone(&self.callbacks);
        thread::spawn(move || {
            while let Ok(event) = rx.lock().unwrap().recv() {
                if let Ok(callbacks) = callbacks.lock() {
                    for callback in callbacks.iter() {
                        callback(event.clone());
                    }
                }
            }
        });

        Ok(())
    }

    /// Stop monitoring socket changes
    pub fn stop(&mut self) {
        self.running = false;
    }
}

impl Drop for SocketMonitor {
    fn drop(&mut self) {
        self.stop();
    }
}
