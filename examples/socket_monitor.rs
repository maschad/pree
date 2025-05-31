use pree::socket::monitor::SocketEvent;
use pree::socket::monitor::SocketMonitor;
use pree::socket::socket::SocketConfig;
use pree::socket::tcp::TcpSocket;
use pree::socket::udp::UdpSocket;
use std::thread;
use std::time::Duration;

fn main() -> pree::Result<()> {
    // Create a socket monitor
    let mut monitor = SocketMonitor::new().interval(Duration::from_secs(1));

    // Register callbacks for socket events
    monitor.on_socket_change(|event| match event {
        SocketEvent::Opened(socket) => {
            println!("New socket opened:");
            println!("  Protocol: {}", socket.protocol);
            println!("  Local: {}", socket.local_addr);
            println!("  Remote: {}", socket.remote_addr);
            println!("  State: {:?}", socket.state);
            if let Some(pid) = socket.process_id {
                println!(
                    "  Process: {} (PID: {})",
                    socket.process_name.unwrap_or_default(),
                    pid
                );
            }
            println!();
        }
        SocketEvent::Closed(socket) => {
            println!("Socket closed:");
            println!("  Protocol: {}", socket.protocol);
            println!("  Local: {}", socket.local_addr);
            println!("  Remote: {}", socket.remote_addr);
            println!();
        }
        SocketEvent::StateChanged(socket) => {
            println!("Socket state changed:");
            println!("  Protocol: {}", socket.protocol);
            println!("  Local: {}", socket.local_addr);
            println!("  Remote: {}", socket.remote_addr);
            println!("  New State: {:?}", socket.state);
            println!();
        }
    })?;

    // Start monitoring
    monitor.start()?;

    // Monitor UDP socket usage
    let udp_sockets = UdpSocket::list()?;
    println!("Current UDP sockets: {}", udp_sockets.len());
    println!("Active UDP connections: {}", UdpSocket::count_active()?);

    // Monitor TCP socket usage
    let tcp_sockets = TcpSocket::list()?;
    println!("Current TCP sockets: {}", tcp_sockets.len());
    println!("Active TCP connections: {}", TcpSocket::count_active()?);

    // Monitor for 30 seconds
    thread::sleep(Duration::from_secs(30));

    // Stop monitoring
    monitor.stop();

    Ok(())
}
