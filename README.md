# Pree

A cross-platform Rust library for network diagnostics and monitoring. Pree provides a unified API for accessing network information across different operating systems.

## Features

- **Interface Overview**
  - List all available network interfaces
  - Get interface details (MAC address, status, MTU, IPs)
  - Interface type detection (loopback, wireless, Ethernet, etc.)
  - Public IP discovery
  - NAT detection

- **Traffic Statistics**
  - Real-time RX/TX bytes and packets
  - Error and drop statistics
  - Bandwidth monitoring
  - Periodic snapshots for delta measurements

- **Routing Table Access**
  - Default gateway information
  - Routing entries with destination, mask, next-hop
  - Route lookup by destination

- **DNS Configuration**
  - System DNS settings
  - Nameserver and search domain information
  - Configurable DNS resolver
  - Forward and reverse lookups
  - DNS record caching with TTL support

- **Socket/Process Visibility** (optional)
  - List open TCP/UDP sockets
  - Process information for sockets
  - Socket state and statistics
  - Filter by process, port, or address
  - Port availability checking
  - Socket binding verification

- **Network Change Detection**
  - Interface change monitoring
  - IP address change detection
  - VPN connection tracking
  - Hot reload support

## Supported Platforms

- Linux
- macOS
- Windows

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
pree = "0.1.0"
```

### Basic Example

```rust
use pree::{Interface, RoutingTable, DnsResolver};

fn main() -> pree::Result<()> {
    // List network interfaces
    let interfaces = Interface::list()?;
    for iface in interfaces {
        println!("{}", iface);
    }

    // Get routing table
    let routes = RoutingTable::get()?;
    println!("{}", routes);

    // DNS resolution
    let resolver = DnsResolver::system()?;
    let ips = resolver.resolve("example.com")?;
    for ip in ips {
        println!("{}", ip);
    }

    Ok(())
}
```

### Interface Discovery and IP Binding

```rust
use pree::{Interface, InterfaceMonitor};
use std::net::IpAddr;

fn main() -> pree::Result<()> {
    // Find suitable interfaces for binding
    let interfaces = Interface::list()?;
    let bindable_interfaces: Vec<_> = interfaces
        .into_iter()
        .filter(|iface| {
            // Filter out loopback and down interfaces
            !iface.is_loopback() && iface.is_up()
        })
        .collect();

    println!("Available interfaces for binding:");
    for iface in &bindable_interfaces {
        println!("  {}: {}", iface.name, iface.ip_addresses().join(", "));
    }

    // Get public IP address
    if let Some(public_ip) = Interface::public_ip()? {
        println!("Public IP: {}", public_ip);
    }

    // Check if behind NAT
    if Interface::is_behind_nat()? {
        println!("System is behind NAT");
    }

    // Monitor interface changes
    let mut monitor = InterfaceMonitor::new()?;
    monitor.on_interface_change(|event| {
        match event {
            InterfaceEvent::Added(iface) => {
                println!("New interface detected: {}", iface.name);
            }
            InterfaceEvent::Removed(iface) => {
                println!("Interface removed: {}", iface.name);
            }
            InterfaceEvent::IpChanged(iface) => {
                println!("IP changed for {}: {}", iface.name, iface.ip_addresses().join(", "));
            }
        }
    })?;

    monitor.start()?;
    // ... rest of the application logic
    Ok(())
}
```

### Port Availability and Binding

```rust
use pree::socket::{get_available_ports, is_port_available, SocketMonitor};
use std::net::{IpAddr, SocketAddr};

fn main() -> pree::Result<()> {
    // Check if port 443 is available on specific IP
    let ip = IpAddr::from_str("192.168.1.100")?;
    let port = 443;
    if is_port_available_on_ip(port, ip)? {
        println!("Port 443 is available on {}", ip);
    }

    // Find available ports in a range
    let start_port = 8000;
    let end_port = 8100;
    let available_ports = get_available_ports_in_range(start_port, end_port)?;
    println!("Available ports in range: {:?}", available_ports);

    // Monitor port availability changes
    let mut monitor = SocketMonitor::new()?;
    monitor.on_socket_change(|event| {
        match event {
            SocketEvent::Opened(socket) => {
                println!("Port {} is now in use by process {}",
                    socket.local_addr.port(),
                    socket.process.as_ref().map(|p| p.pid).unwrap_or(0));
            }
            SocketEvent::Closed(socket) => {
                println!("Port {} is now available", socket.local_addr.port());
            }
            _ => {}
        }
    })?;

    monitor.start()?;
    Ok(())
}
```

### DNS Resolution and Caching

```rust
use pree::dns::{DnsResolver, DnsCache, RecordType};
use std::time::Duration;

fn main() -> pree::Result<()> {
    // Create a DNS resolver with caching
    let mut resolver = DnsResolver::builder()
        .cache(DnsCache::new())
        .timeout(Duration::from_secs(5))
        .build()?;

    // Lookup A records
    let records = resolver.lookup("example.com", RecordType::A)?;
    for record in records {
        println!("A record: {}", record);
    }

    // Check cache TTL
    if let Some(ttl) = resolver.get_cache_ttl("example.com", RecordType::A)? {
        println!("Cache TTL: {} seconds", ttl.as_secs());
    }

    // Force refresh cache
    resolver.refresh_cache("example.com", RecordType::A)?;

    Ok(())
}
```

### Socket and Process Tracking

```rust
use pree::socket::{Socket, SocketFilter, SocketMonitor};

fn main() -> pree::Result<()> {
    // Find process using port 8080
    let filter = SocketFilter::new()
        .local_port(8080);

    if let Some(socket) = Socket::find_first(filter)? {
        println!("Port 8080 is used by process {} ({})",
            socket.process.as_ref().map(|p| p.pid).unwrap_or(0),
            socket.process.as_ref().and_then(|p| p.name.clone()).unwrap_or_default());
    }

    // List all open ports
    let sockets = Socket::list()?;
    println!("Open ports:");
    for socket in sockets {
        println!("  {}:{} -> {} (PID: {})",
            socket.local_addr.ip(),
            socket.local_addr.port(),
            socket.remote_addr.map(|addr| format!("{}:{}", addr.ip(), addr.port())).unwrap_or_default(),
            socket.process.as_ref().map(|p| p.pid).unwrap_or(0));
    }

    Ok(())
}
```

### Network Change Detection

```rust
use pree::{InterfaceMonitor, NetworkChangeDetector};
use std::time::Duration;

fn main() -> pree::Result<()> {
    // Create a network change detector
    let mut detector = NetworkChangeDetector::new()?;

    // Monitor interface changes
    detector.on_interface_change(|event| {
        match event {
            NetworkEvent::InterfaceAdded(iface) => {
                println!("New interface: {}", iface.name);
            }
            NetworkEvent::InterfaceRemoved(iface) => {
                println!("Interface removed: {}", iface.name);
            }
            NetworkEvent::IpChanged(iface) => {
                println!("IP changed for {}: {}", iface.name, iface.ip_addresses().join(", "));
            }
            NetworkEvent::VpnConnected(iface) => {
                println!("VPN connected: {}", iface.name);
            }
            NetworkEvent::VpnDisconnected(iface) => {
                println!("VPN disconnected: {}", iface.name);
            }
        }
    })?;

    // Start monitoring with 1-second interval
    detector.start(Duration::from_secs(1))?;

    // ... rest of the application logic
    Ok(())
}
```

## Optional Features

- `async`: Enable async/await support
- `serde`: Enable serialization/deserialization
- `socket-tracking`: Enable process-level socket tracking
- `dns-cache`: Enable DNS record caching
- `nat-detection`: Enable NAT detection features

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Real-World Use Cases

### 1. UDP Socket Capacity Monitoring

Monitor UDP socket usage and system limits to prevent resource exhaustion:

```rust
use pree::socket::{UdpSocket, get_system_socket_limit};
use std::thread;
use std::time::Duration;

fn main() -> pree::Result<()> {
    let max_sockets = get_system_socket_limit()?;
    let warning_threshold = (max_sockets as f64 * 0.8) as usize;

    loop {
        let active_sockets = UdpSocket::count_active()?;
        let usage_percent = (active_sockets as f64 / max_sockets as f64) * 100.0;

        println!("UDP Socket Usage: {}/{} ({:.1}%)",
            active_sockets, max_sockets, usage_percent);

        if active_sockets >= warning_threshold {
            println!("WARNING: UDP socket usage above 80%!");
        }

        thread::sleep(Duration::from_secs(5));
    }
}
```

### 2. Application Socket Monitoring

Track socket usage by specific applications and monitor port availability:

```rust
use pree::socket::{SocketMonitor, SocketEvent, TcpSocket, is_port_available};
use std::net::SocketAddr;
use std::str::FromStr;

fn main() -> pree::Result<()> {
    // Monitor sockets for a specific application
    let target_pid = 1234; // Replace with actual PID
    let mut monitor = SocketMonitor::new();

    monitor.on_socket_change(move |event| {
        if let Some(process) = &event.socket().process {
            if process.pid == target_pid {
                match event {
                    SocketEvent::Opened(socket) => {
                        println!("Application opened socket on port {}",
                            socket.local_addr.port());
                    }
                    SocketEvent::Closed(socket) => {
                        println!("Application closed socket on port {}",
                            socket.local_addr.port());
                    }
                    _ => {}
                }
            }
        }
    })?;

    // Check if required ports are available
    let required_ports = [8080, 8081, 8082];
    for port in required_ports {
        if is_port_available(port)? {
            println!("Port {} is available for use", port);
        } else {
            println!("WARNING: Port {} is already in use", port);
        }
    }

    monitor.start()?;
    // ... rest of the application logic
    Ok(())
}
```
