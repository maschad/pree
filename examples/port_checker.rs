use pree::socket::platform::{get_available_ports, get_system_socket_limit, is_port_available};

fn main() -> pree::Result<()> {
    // Get system socket limit
    let max_sockets = get_system_socket_limit()?;
    println!("System socket limit: {max_sockets}");

    // Check specific ports
    let ports_to_check = [80, 443, 8080, 3000, 5432];
    println!("\nChecking specific ports:");
    for port in ports_to_check {
        let available = is_port_available(port)?;
        println!(
            "Port {port}: {}",
            if available { "Available" } else { "In Use" }
        );
    }

    // Get all available ports
    println!("\nGetting all available ports...");
    let available_ports = get_available_ports()?;
    println!("Found {} available ports", available_ports.len());

    // Print first 10 available ports
    println!("\nFirst 10 available ports:");
    for port in available_ports.iter().take(10) {
        println!("  {port}");
    }

    // Check if we can bind to a specific port
    let test_port = 12345;
    if is_port_available(test_port)? {
        println!("\nPort {test_port} is available for binding");
        // Here you could attempt to bind to the port
        // let listener = TcpListener::bind(format!("127.0.0.1:{test_port}"))?;
    } else {
        println!("\nPort {test_port} is already in use");
    }

    Ok(())
}
