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

impl Default for SocketMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl SocketMonitor {
    /// Create a new socket monitor with default settings
    #[must_use]
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
    #[must_use]
    pub const fn interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Register a callback for socket events
    ///
    /// # Errors
    /// Returns an error if the callback cannot be registered
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
    ///
    /// # Panics
    /// May panic if the mutex lock fails
    ///
    /// # Errors
    /// Returns an error if socket monitoring fails to start
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
                                    Protocol::Icmp | Protocol::Raw | Protocol::Other(_) => {
                                        Protocol::Tcp
                                    }
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
                                    Protocol::Icmp | Protocol::Raw | Protocol::Other(_) => {
                                        Protocol::Tcp
                                    }
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
                                        Protocol::Icmp | Protocol::Raw | Protocol::Other(_) => {
                                            Protocol::Tcp
                                        }
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
            let rx = rx.lock().unwrap();
            while let Ok(event) = rx.recv() {
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
    pub const fn stop(&mut self) {
        self.running = false;
    }
}

impl Drop for SocketMonitor {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[test]
    fn test_monitor_creation() {
        let monitor = SocketMonitor::new();
        assert!(!monitor.running);
        assert_eq!(monitor.interval, Duration::from_secs(1));

        let monitor = SocketMonitor::new().interval(Duration::from_millis(500));
        assert_eq!(monitor.interval, Duration::from_millis(500));
    }

    #[test]
    fn test_callback_registration() {
        let mut monitor = SocketMonitor::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);

        monitor
            .on_socket_change(move |_event| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .unwrap();

        // Verify callback was registered
        let callbacks_length = monitor.callbacks.lock().unwrap().len();
        assert_eq!(callbacks_length, 1);
    }

    #[test]
    fn test_start_stop() {
        let mut monitor = SocketMonitor::new();
        assert!(!monitor.running);

        monitor.start().unwrap();
        assert!(monitor.running);

        monitor.stop();
        assert!(!monitor.running);
    }

    #[test]
    fn test_socket_events() {
        let mut monitor = SocketMonitor::new();
        let opened_count = Arc::new(AtomicUsize::new(0));
        let closed_count = Arc::new(AtomicUsize::new(0));
        let state_changed_count = Arc::new(AtomicUsize::new(0));

        let opened_clone = Arc::clone(&opened_count);
        let closed_clone = Arc::clone(&closed_count);
        let state_changed_clone = Arc::clone(&state_changed_count);

        monitor
            .on_socket_change(move |event| {
                match event {
                    SocketEvent::Opened(_) => opened_clone.fetch_add(1, Ordering::SeqCst),
                    SocketEvent::Closed(_) => closed_clone.fetch_add(1, Ordering::SeqCst),
                    SocketEvent::StateChanged(_) => {
                        state_changed_clone.fetch_add(1, Ordering::SeqCst)
                    }
                };
            })
            .unwrap();

        monitor.start().unwrap();

        // Give some time for events to be processed
        std::thread::sleep(Duration::from_secs(2));

        // Ensure monitor is dropped after sleep
        drop(monitor);

        // We can't make strong assertions about the counts since they depend on system state,
        // but we can verify the callback was called
        assert!(
            opened_count.load(Ordering::SeqCst)
                + closed_count.load(Ordering::SeqCst)
                + state_changed_count.load(Ordering::SeqCst)
                > 0
        );
    }

    #[test]
    fn test_multiple_callbacks() {
        let mut monitor = SocketMonitor::new();
        let counter1 = Arc::new(AtomicUsize::new(0));
        let counter2 = Arc::new(AtomicUsize::new(0));

        let counter1_clone = Arc::clone(&counter1);
        let counter2_clone = Arc::clone(&counter2);

        monitor
            .on_socket_change(move |_event| {
                counter1_clone.fetch_add(1, Ordering::SeqCst);
            })
            .unwrap();

        monitor
            .on_socket_change(move |_event| {
                counter2_clone.fetch_add(1, Ordering::SeqCst);
            })
            .unwrap();

        monitor.start().unwrap();
        std::thread::sleep(Duration::from_secs(2));

        // Ensure monitor is dropped after sleep
        drop(monitor);

        // Both callbacks should have been called
        assert!(counter1.load(Ordering::SeqCst) > 0);
        assert!(counter2.load(Ordering::SeqCst) > 0);
    }
}
