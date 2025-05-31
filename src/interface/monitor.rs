use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::Duration;

use crate::interface::Interface;
use crate::{NetworkError, Result};

/// Events that can occur for network interfaces
#[derive(Debug, Clone)]
pub enum InterfaceEvent {
    /// A new interface was added
    Added(Interface),
    /// An interface was removed
    Removed(Interface),
    /// An interface's IP address changed
    IpChanged(Interface),
    /// A VPN interface was connected
    VpnConnected(Interface),
    /// A VPN interface was disconnected
    VpnDisconnected(Interface),
}

/// Callback function type for interface events
pub type InterfaceCallback = Box<dyn Fn(InterfaceEvent) + Send + 'static>;

/// Monitors network interface changes
pub struct InterfaceMonitor {
    tx: Sender<InterfaceEvent>,
    rx: Receiver<InterfaceEvent>,
    callbacks: Vec<InterfaceCallback>,
    interval: Duration,
    running: bool,
}

impl InterfaceMonitor {
    /// Create a new interface monitor
    pub fn new() -> Result<Self> {
        let (tx, rx) = channel();
        Ok(Self {
            tx,
            rx,
            callbacks: Vec::new(),
            interval: Duration::from_secs(1),
            running: false,
        })
    }

    /// Set the polling interval
    pub fn interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Register a callback for interface events
    pub fn on_interface_change<F>(&mut self, callback: F) -> Result<()>
    where
        F: Fn(InterfaceEvent) + Send + 'static,
    {
        self.callbacks.push(Box::new(callback));
        Ok(())
    }

    /// Start monitoring interface changes
    pub fn start(&mut self) -> Result<()> {
        if self.running {
            return Ok(());
        }

        self.running = true;
        let tx = self.tx.clone();
        let interval = self.interval;

        thread::spawn(move || {
            let mut previous_interfaces = HashSet::new();

            while let Ok(interfaces) = Interface::list() {
                let current_interfaces: HashSet<_> = interfaces.into_iter().collect();

                // Find new interfaces
                for interface in &current_interfaces {
                    if !previous_interfaces.contains(interface) {
                        let _ = tx.send(InterfaceEvent::Added(interface.clone()));
                    }
                }

                // Find removed interfaces
                for interface in &previous_interfaces {
                    if !current_interfaces.contains(interface) {
                        let _ = tx.send(InterfaceEvent::Removed(interface.clone()));
                    }
                }

                // Check for IP changes and VPN status
                for interface in &current_interfaces {
                    if let Some(prev_interface) = previous_interfaces.get(interface) {
                        if interface.ip_addresses() != prev_interface.ip_addresses() {
                            let _ = tx.send(InterfaceEvent::IpChanged(interface.clone()));
                        }

                        // Check VPN status
                        if interface.is_vpn() && !prev_interface.is_vpn() {
                            let _ = tx.send(InterfaceEvent::VpnConnected(interface.clone()));
                        } else if !interface.is_vpn() && prev_interface.is_vpn() {
                            let _ = tx.send(InterfaceEvent::VpnDisconnected(interface.clone()));
                        }
                    }
                }

                previous_interfaces = current_interfaces;
                thread::sleep(interval);
            }
        });

        // Start event processing thread
        let callbacks = self.callbacks.clone();
        thread::spawn(move || {
            while let Ok(event) = self.rx.recv() {
                for callback in &callbacks {
                    callback(event.clone());
                }
            }
        });

        Ok(())
    }

    /// Stop monitoring interface changes
    pub fn stop(&mut self) {
        self.running = false;
    }
}

impl Drop for InterfaceMonitor {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Detects network changes including interface, IP, and VPN status
pub struct NetworkChangeDetector {
    monitor: InterfaceMonitor,
}

impl NetworkChangeDetector {
    /// Create a new network change detector
    pub fn new() -> Result<Self> {
        Ok(Self {
            monitor: InterfaceMonitor::new()?,
        })
    }

    /// Set the polling interval
    pub fn interval(mut self, interval: Duration) -> Self {
        self.monitor = self.monitor.interval(interval);
        self
    }

    /// Register a callback for network changes
    pub fn on_interface_change<F>(&mut self, callback: F) -> Result<()>
    where
        F: Fn(InterfaceEvent) + Send + 'static,
    {
        self.monitor.on_interface_change(callback)
    }

    /// Start detecting network changes
    pub fn start(&mut self, interval: Duration) -> Result<()> {
        self.monitor = self.monitor.interval(interval);
        self.monitor.start()
    }

    /// Stop detecting network changes
    pub fn stop(&mut self) {
        self.monitor.stop();
    }
}

impl Drop for NetworkChangeDetector {
    fn drop(&mut self) {
        self.stop();
    }
}
