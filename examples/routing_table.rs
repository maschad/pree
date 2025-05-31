use pree::routing::{RouteEvent, RouteMonitor, RoutingTable};
use std::net::IpAddr;
use std::str::FromStr;
use std::thread;
use std::time::Duration;

fn main() -> pree::Result<()> {
    // Get the current routing table
    let routes = RoutingTable::get()?;
    println!("Current Routing Table:");
    for route in &routes.routes {
        println!("\nRoute:");
        println!("  Destination: {}", route.destination);
        println!(
            "  Gateway: {}",
            route.gateway.map_or("None".to_string(), |g| g.to_string())
        );
        println!("  Interface: {}", route.interface);
        println!("  Metric: {}", route.metric);
    }

    // Get default gateway
    if let Some(default_gateway) = routes.default_gateway() {
        println!("\nDefault Gateway:");
        println!("  IP: {}", default_gateway.destination);
        println!("  Interface: {}", default_gateway.interface);
    }

    // Lookup route for specific IP
    let test_ips = [
        "8.8.8.8",     // Google DNS
        "192.168.1.1", // Common local gateway
        "10.0.0.1",    // Private network
    ];

    println!("\nRoute Lookups:");
    for ip_str in test_ips {
        if let Ok(ip) = IpAddr::from_str(ip_str) {
            if let Some(route) = routes.find_route(ip) {
                println!("\nRoute for {ip}:");
                println!(
                    "  Via: {}",
                    route.gateway.map_or("None".to_string(), |g| g.to_string())
                );
                println!("  Interface: {}", route.interface);
            } else {
                println!("\nNo route found for {ip}");
            }
        }
    }

    // Monitor routing table changes
    let mut monitor = RouteMonitor::new()?;
    monitor.on_route_change(|event| match event {
        RouteEvent::Added(route) => {
            println!("\nNew route added:");
            println!("  Destination: {}", route.destination);
            println!(
                "  Gateway: {}",
                route.gateway.map_or("None".to_string(), |g| g.to_string())
            );
        }
        RouteEvent::Removed(route) => {
            println!("\nRoute removed:");
            println!("  Destination: {}", route.destination);
            println!(
                "  Gateway: {}",
                route.gateway.map_or("None".to_string(), |g| g.to_string())
            );
        }
        RouteEvent::Changed(old_route, new_route) => {
            println!("\nRoute changed:");
            println!("  Destination: {}", new_route.destination);
            println!(
                "  Old Gateway: {}",
                old_route
                    .gateway
                    .map_or("None".to_string(), |g| g.to_string())
            );
            println!(
                "  New Gateway: {}",
                new_route
                    .gateway
                    .map_or("None".to_string(), |g| g.to_string())
            );
        }
    })?;

    // Start monitoring
    monitor.start()?;

    // Monitor for 30 seconds
    thread::sleep(Duration::from_secs(30));

    // Stop monitoring
    monitor.stop();

    Ok(())
}
