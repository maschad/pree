use pree::socket::monitor::{SocketEvent, SocketMonitor};
use pree::socket::platform::{CongestionControl, CongestionState, SocketStats};
use std::thread;
use std::time::Duration;

fn main() -> pree::Result<()> {
    // Create a socket monitor with a shorter interval for more frequent updates
    let mut monitor = SocketMonitor::new().interval(Duration::from_millis(500));

    // Register callbacks for socket events with analysis
    monitor.on_socket_change(|event| match event {
        SocketEvent::Opened(socket) => {
            println!("New socket opened:");
            print_socket_info(&socket);
            if let Some(stats) = &socket.stats {
                analyze_socket_stats(stats);
            }
            println!();
        }
        SocketEvent::Closed(socket) => {
            println!("Socket closed:");
            print_socket_info(&socket);
            if let Some(stats) = &socket.stats {
                analyze_socket_stats(stats);
            }
            println!();
        }
        SocketEvent::StateChanged(socket) => {
            println!("Socket state changed:");
            print_socket_info(&socket);
            if let Some(stats) = &socket.stats {
                analyze_socket_stats(stats);
            }
            println!();
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

fn print_socket_info(socket: &pree::socket::platform::SocketInfo) {
    println!("  Protocol: {}", socket.protocol);
    println!("  Local: {}", socket.local_addr);
    println!("  Remote: {}", socket.remote_addr);
    println!("  State: {:?}", socket.state);
    if let Some(pid) = socket.process_id {
        println!(
            "  Process: {} (PID: {})",
            socket.process_name.as_deref().unwrap_or("unknown"),
            pid
        );
    }
}

fn analyze_socket_stats(stats: &SocketStats) {
    println!("  Connection Analysis:");

    // Basic metrics
    println!(
        "    Bytes sent/received: {}/{}",
        stats.bytes_sent, stats.bytes_received
    );
    println!(
        "    Packets sent/received: {}/{}",
        stats.packets_sent, stats.packets_received
    );
    println!("    Retransmits: {}", stats.retransmits);

    // RTT analysis
    if let Some(rtt) = stats.rtt {
        println!("    RTT: {:.2}ms", rtt.as_secs_f32() * 1000.0);
        if let Some(rtt_var) = stats.rtt_variance {
            println!("    RTT variance: {:.2}ms", rtt_var.as_secs_f32() * 1000.0);
        }
    }

    // Congestion control analysis
    if let Some(cc) = &stats.congestion_control {
        println!("    Congestion Control: {cc:?}");
        match cc {
            CongestionControl::Cubic => {
                println!("      Using CUBIC algorithm for high-speed networks");
            }
            CongestionControl::Bbr => {
                println!("      Using BBR for better throughput and latency");
            }
            CongestionControl::Reno => {
                println!("      Using Reno for basic congestion control");
            }
            CongestionControl::Vegas => {
                println!("      Using Vegas for proactive congestion avoidance");
            }
            CongestionControl::Westwood => {
                println!("      Using Westwood for wireless networks");
            }
            CongestionControl::Other(s) => println!("      Using custom algorithm: {s}"),
        }
    }
    if let Some(state) = &stats.congestion_state {
        println!("    Congestion State: {state:?}");
        match state {
            CongestionState::SlowStart => {
                println!("      In slow start phase - growing window exponentially");
            }
            CongestionState::CongestionAvoidance => {
                println!("      In congestion avoidance - growing window linearly");
            }
            CongestionState::FastRecovery => {
                println!("      In fast recovery - recovering from packet loss");
            }
            CongestionState::FastRetransmit => {
                println!("      In fast retransmit - retransmitting lost packets");
            }
            CongestionState::Other(s) => println!("      In custom state: {s}"),
        }
    }
    if stats.is_congested() {
        println!("    ⚠️  Connection is experiencing congestion");
    }

    // Connection quality analysis
    let quality_score = stats.calculate_quality_score();
    println!(
        "    Connection Quality Score: {:.1}%",
        quality_score * 100.0
    );

    if let Some(util) = stats.bandwidth_utilization() {
        println!("    Bandwidth Utilization: {util:.1}%");
    }

    let loss_rate = stats.packet_loss_rate();
    if loss_rate > 0.0 {
        println!("    Packet Loss Rate: {loss_rate:.1}%");
    }

    if stats.has_buffer_bloat() {
        println!("    ⚠️  Buffer bloat detected");
    }

    // SACK and ECN analysis
    if stats.sack_enabled {
        println!("    SACK enabled");
        if let Some(blocks) = stats.sack_blocks {
            println!("    SACK blocks: {blocks}");
        }
        if let Some(reordering) = stats.sack_reordering {
            println!("    SACK reordering events: {reordering}");
        }
    }

    if stats.ecn_enabled {
        println!("    ECN enabled");
        if let Some(ce_count) = stats.ecn_ce_count {
            println!("    ECN Congestion Experienced count: {ce_count}");
        }
    }

    // Window analysis
    if let (Some(send_win), Some(recv_win)) = (stats.send_window, stats.receive_window) {
        println!("    Send/Receive Window: {send_win}/{recv_win}");
    }
    if let Some(zero_win) = stats.zero_window_events {
        if zero_win > 0 {
            println!("    ⚠️  Zero window events: {zero_win}");
        }
    }

    // Connection duration
    if let Some(duration) = stats.connection_duration {
        println!("    Connection Duration: {:.1}s", duration.as_secs_f32());
    }
}
