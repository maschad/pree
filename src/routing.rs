use crate::{types::IpNetwork, NetworkError};
use std::net::IpAddr;
use std::thread;
use std::time::Duration;

pub type Result<T> = std::result::Result<T, NetworkError>;

/// Represents a routing table entry
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub destination: IpNetwork,
    pub gateway: Option<IpAddr>,
    pub interface: String,
    pub metric: u32,
}

/// Represents the system routing table
#[derive(Debug, Clone)]
pub struct RoutingTable {
    pub routes: Vec<Route>,
    pub default_gateway: Option<Route>,
}

/// Events that can occur for routing table entries
#[derive(Debug, Clone)]
pub enum RouteEvent {
    /// A new route was added
    Added(Route),
    /// A route was removed
    Removed(Route),
    /// A route was changed
    Changed(Route, Route),
}

/// Monitors routing table changes
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RouteMonitor {
    interval: Duration,
    running: bool,
}

impl RouteMonitor {
    /// Create a new route monitor
    ///
    /// # Errors
    /// Returns an error if the monitor cannot be initialized
    pub const fn new() -> Result<Self> {
        Ok(Self {
            interval: Duration::from_secs(1),
            running: false,
        })
    }

    /// Register a callback for route changes
    ///
    /// # Errors
    /// Returns an error if the callback cannot be registered
    pub fn on_route_change<F>(&mut self, callback: F) -> Result<()>
    where
        F: Fn(RouteEvent) + Send + 'static,
    {
        let mut previous_routes = RoutingTable::get()?;

        thread::spawn(move || {
            while let Ok(current_routes) = RoutingTable::get() {
                // Find new routes
                for route in &current_routes.routes {
                    if !previous_routes.routes.contains(route) {
                        callback(RouteEvent::Added(route.clone()));
                    }
                }

                // Find removed routes
                for route in &previous_routes.routes {
                    if !current_routes.routes.contains(route) {
                        callback(RouteEvent::Removed(route.clone()));
                    }
                }

                // Check for route changes
                for route in &current_routes.routes {
                    if let Some(old_route) = previous_routes
                        .routes
                        .iter()
                        .find(|r| r.destination == route.destination)
                    {
                        if old_route != route {
                            callback(RouteEvent::Changed(old_route.clone(), route.clone()));
                        }
                    }
                }

                previous_routes = current_routes;
                thread::sleep(Duration::from_secs(1));
            }
        });

        Ok(())
    }

    /// Start monitoring route changes
    ///
    /// # Errors
    /// Returns an error if monitoring cannot be started
    pub const fn start(&mut self) -> Result<()> {
        self.running = true;
        Ok(())
    }

    /// Stop monitoring route changes
    pub const fn stop(&mut self) {
        self.running = false;
    }
}

impl RoutingTable {
    /// Get the current routing table
    ///
    /// # Errors
    /// Returns an error if the routing table cannot be retrieved
    pub fn get() -> Result<Self> {
        #[cfg(unix)]
        {
            Ok(crate::platform::get_routing_table()?)
        }
        #[cfg(windows)]
        {
            crate::platform::get_routing_table()
        }
    }

    /// Find a route for a specific destination
    #[must_use]
    pub fn find_route(&self, destination: IpAddr) -> Option<&Route> {
        self.routes
            .iter()
            .find(|route| match (destination, &route.destination) {
                (IpAddr::V4(ip), net) => net.addr == IpAddr::V4(ip),
                (IpAddr::V6(ip), net) => net.addr == IpAddr::V6(ip),
            })
    }

    /// Get the default gateway
    #[must_use]
    pub const fn default_gateway(&self) -> Option<&Route> {
        self.default_gateway.as_ref()
    }
}

impl std::fmt::Display for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.destination)?;
        if let Some(gateway) = self.gateway {
            write!(f, " via {gateway}")?;
        }
        write!(f, " dev {} metric {}", self.interface, self.metric)
    }
}

impl std::fmt::Display for RoutingTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Kernel IP routing table")?;
        writeln!(
            f,
            "Destination         Gateway         Interface       Metric"
        )?;

        for route in &self.routes {
            writeln!(f, "{route}")?;
        }

        Ok(())
    }
}
