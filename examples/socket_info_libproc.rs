//! Example demonstrating socket information retrieval using libproc
//! 
//! This example shows how to get detailed socket information programmatically
//! without relying on command-line tools.

use pree::socket::platform::{get_sockets_info, SocketState};
use pree::Protocol;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Socket Information using libproc ===\n");
    
    // Get all socket information
    let sockets = get_sockets_info()?;
    
    println!("Found {} sockets\n", sockets.len());
    
    // Group sockets by protocol
    let mut tcp_sockets = Vec::new();
    let mut udp_sockets = Vec::new();
    
    for socket in sockets {
        match socket.protocol {
            Protocol::Tcp => tcp_sockets.push(socket),
            Protocol::Udp => udp_sockets.push(socket),
            _ => {}
        }
    }
    
    // Display TCP sockets
    println!("TCP Sockets ({}):", tcp_sockets.len());
    println!("{:<25} {:<25} {:<15} {:<10} {}", 
        "Local Address", "Remote Address", "State", "PID", "Process");
    println!("{}", "-".repeat(90));
    
    for socket in tcp_sockets.iter().take(10) {
        println!("{:<25} {:<25} {:<15} {:<10} {}", 
            socket.local_addr.to_string(),
            socket.remote_addr.to_string(),
            format!("{:?}", socket.state),
            socket.process_id.map_or("N/A".to_string(), |p| p.to_string()),
            socket.process_name.as_deref().unwrap_or("Unknown")
        );
        
        // Display socket stats if available
        if let Some(stats) = &socket.stats {
            println!("  └─ Stats: RTT={:?}, CWnd={:?}, Retransmits={}", 
                stats.rtt,
                stats.congestion_window,
                stats.retransmits
            );
            
            // Check connection health
            let quality_score = stats.calculate_quality_score();
            let packet_loss = stats.packet_loss_rate();
            println!("  └─ Quality: {:.1}%, Packet Loss: {:.2}%", 
                quality_score * 100.0, packet_loss);
            
            if stats.has_buffer_bloat() {
                println!("  └─ ⚠️  Buffer bloat detected!");
            }
            
            let issues = stats.performance_issues();
            if !issues.is_empty() {
                println!("  └─ Issues: {}", issues.join(", "));
            }
        }
    }
    
    if tcp_sockets.len() > 10 {
        println!("... and {} more TCP sockets", tcp_sockets.len() - 10);
    }
    
    println!();
    
    // Display UDP sockets
    println!("UDP Sockets ({}):", udp_sockets.len());
    println!("{:<25} {:<25} {:<10} {}", 
        "Local Address", "Remote Address", "PID", "Process");
    println!("{}", "-".repeat(70));
    
    for socket in udp_sockets.iter().take(10) {
        println!("{:<25} {:<25} {:<10} {}", 
            socket.local_addr.to_string(),
            socket.remote_addr.to_string(),
            socket.process_id.map_or("N/A".to_string(), |p| p.to_string()),
            socket.process_name.as_deref().unwrap_or("Unknown")
        );
    }
    
    if udp_sockets.len() > 10 {
        println!("... and {} more UDP sockets", udp_sockets.len() - 10);
    }
    
    println!();
    
    // Show listening sockets
    let listening = tcp_sockets.iter()
        .filter(|s| matches!(s.state, SocketState::Listen))
        .collect::<Vec<_>>();
    
    if !listening.is_empty() {
        println!("Listening TCP Sockets:");
        for socket in listening {
            println!("  - {} (PID: {}, Process: {})",
                socket.local_addr,
                socket.process_id.map_or("N/A".to_string(), |p| p.to_string()),
                socket.process_name.as_deref().unwrap_or("Unknown")
            );
        }
    }
    
    Ok(())
}