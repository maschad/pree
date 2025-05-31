use ipnetwork::IpNetwork;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{NetworkError, Result};

/// Represents a routing table entry
#[derive(Debug, Clone)]
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

impl RoutingTable {
    /// Get the current routing table
    pub fn get() -> Result<Self> {
        #[cfg(unix)]
        {
            crate::platform::get_routing_table()
        }
        #[cfg(windows)]
        {
            crate::platform::get_routing_table()
        }
    }

    /// Find a route for a specific destination
    pub fn find_route(&self, destination: IpAddr) -> Option<&Route> {
        self.routes
            .iter()
            .find(|route| match (destination, route.destination) {
                (IpAddr::V4(ip), IpNetwork::V4(net)) => net.contains(ip),
                (IpAddr::V6(ip), IpNetwork::V6(net)) => net.contains(ip),
                _ => false,
            })
    }

    /// Get the default gateway
    pub fn default_gateway(&self) -> Option<&Route> {
        self.default_gateway.as_ref()
    }
}

impl std::fmt::Display for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.destination)?;
        if let Some(gateway) = self.gateway {
            write!(f, " via {}", gateway)?;
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
            writeln!(f, "{}", route)?;
        }

        Ok(())
    }
}
