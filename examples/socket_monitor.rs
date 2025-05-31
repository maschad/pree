use pree::socket::{SocketEvent, SocketMonitor, TcpSocket, UdpSocket};
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
            if let Some(remote) = socket.remote_addr {
                println!("  Remote: {}", remote);
            }
            println!("  State: {:?}", socket.state);
            if let Some(process) = &socket.process {
                println!("  Process: {} (PID: {})", process.name, process.pid);
            }
            println!();
        }
        SocketEvent::Closed(socket) => {
            println!("Socket closed:");
            println!("  Protocol: {}", socket.protocol);
            println!("  Local: {}", socket.local_addr);
            if let Some(remote) = socket.remote_addr {
                println!("  Remote: {}", remote);
            }
            println!();
        }
        SocketEvent::StateChanged(socket) => {
            println!("Socket state changed:");
            println!("  Protocol: {}", socket.protocol);
            println!("  Local: {}", socket.local_addr);
            if let Some(remote) = socket.remote_addr {
                println!("  Remote: {}", remote);
            }
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
