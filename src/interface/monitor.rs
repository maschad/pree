use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::thread;
use std::time::Duration;

use crate::interface::{Interface, InterfaceStats};
use crate::Result;

impl Hash for Interface {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
    }
}

impl PartialEq for Interface {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for Interface {}

/// Events that can occur for network interfaces
#[derive(Debug, Clone)]
pub enum InterfaceEvent {
    /// A new interface was added
    Added(Interface),
    /// An interface was removed
    Removed(Interface),
    /// An interface's IP address changed
    IpChanged(Interface),
    /// An interface's statistics changed
    StatsChanged(Interface, InterfaceStats),
    /// A VPN interface was connected
    VpnConnected(Interface),
    /// A VPN interface was disconnected
    VpnDisconnected(Interface),
}

/// Callback function type for interface events
pub type InterfaceCallback = Box<dyn Fn(InterfaceEvent) + Send + 'static>;

/// Monitors network interface changes
pub struct InterfaceMonitor {
    callbacks: Vec<InterfaceCallback>,
    interval: Duration,
    running: bool,
}

impl InterfaceMonitor {
    /// Create a new interface monitor
    ///
    /// # Errors
    /// Returns an error if the monitor cannot be initialized
    pub fn new() -> Result<Self> {
        Ok(Self {
            callbacks: Vec::new(),
            interval: Duration::from_secs(1),
            running: false,
        })
    }

    /// Set the polling interval
    #[must_use]
    pub const fn interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Register a callback for interface events
    ///
    /// # Errors
    /// Returns an error if the callback cannot be registered
    pub fn on_interface_change<F>(&mut self, callback: F) -> Result<()>
    where
        F: Fn(InterfaceEvent) + Send + 'static,
    {
        self.callbacks.push(Box::new(callback));
        Ok(())
    }

    /// Start monitoring interface changes
    ///
    /// # Errors
    /// Returns an error if monitoring cannot be started
    pub fn start(&mut self) -> Result<()> {
        if self.running {
            return Ok(());
        }

        self.running = true;
        let interval = self.interval;
        let callbacks = std::mem::take(&mut self.callbacks);

        thread::spawn(move || {
            let mut previous_interfaces: HashSet<Interface> = HashSet::new();

            while let Ok(interfaces) = Interface::list() {
                let current_interfaces: HashSet<Interface> = interfaces.into_iter().collect();

                // Find new interfaces
                for interface in &current_interfaces {
                    if !previous_interfaces.contains(interface) {
                        let event = InterfaceEvent::Added(interface.clone());
                        for callback in &callbacks {
                            callback(event.clone());
                        }
                    }
                }

                // Find removed interfaces
                for interface in &previous_interfaces {
                    if !current_interfaces.contains(interface) {
                        let event = InterfaceEvent::Removed(interface.clone());
                        for callback in &callbacks {
                            callback(event.clone());
                        }
                    }
                }

                // Check for IP changes
                for interface in &current_interfaces {
                    if let Some(prev_interface) = previous_interfaces.get(interface) {
                        if interface.ipv4 != prev_interface.ipv4
                            || interface.ipv6 != prev_interface.ipv6
                        {
                            let event = InterfaceEvent::IpChanged(interface.clone());
                            for callback in &callbacks {
                                callback(event.clone());
                            }
                        }
                    }
                }

                previous_interfaces = current_interfaces;
                thread::sleep(interval);
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
    ///
    /// # Errors
    /// Returns an error if the detector cannot be initialized
    #[allow(dead_code)]
    pub fn new() -> Result<Self> {
        Ok(Self {
            monitor: InterfaceMonitor::new()?,
        })
    }

    /// Set the polling interval
    #[allow(dead_code)]
    pub fn interval(&mut self, interval: Duration) {
        self.monitor.interval = interval;
    }

    /// Register a callback for network changes
    #[allow(dead_code)]
    pub fn on_interface_change<F>(&mut self, callback: F) -> Result<()>
    where
        F: Fn(InterfaceEvent) + Send + 'static,
    {
        self.monitor.on_interface_change(callback)
    }

    /// Start detecting network changes
    ///
    /// # Errors
    /// Returns an error if monitoring cannot be started
    #[allow(dead_code)]
    pub fn start(&mut self, interval: Duration) -> Result<()> {
        self.monitor.interval = interval;
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
