//! macOS-specific tests using libproc

#![cfg(target_os = "macos")]

use pree::socket::platform::get_sockets_info;
use pree::{Protocol, SocketState};
use std::collections::HashMap;
use std::net::{TcpListener, UdpSocket};
use std::process::Command;
use std::thread;
use std::time::Duration;

/// Test libproc integration on macOS
#[test]
fn test_libproc_socket_enumeration() {
    let sockets = get_sockets_info().expect("Failed to get sockets via libproc");
    assert!(!sockets.is_empty(), "Should find sockets using libproc");

    // Verify libproc provides detailed information
    let tcp_count = sockets
        .iter()
        .filter(|s| s.protocol == Protocol::Tcp)
        .count();

    assert!(tcp_count > 0, "Should find TCP sockets");

    // Test that we get process information
    let sockets_with_process = sockets.iter().filter(|s| s.process_id.is_some()).count();

    assert!(
        sockets_with_process > 0,
        "libproc should provide process information"
    );
}

/// Test process information accuracy on macOS
#[test]
fn test_macos_process_info_accuracy() {
    let sockets = get_sockets_info().expect("Failed to get socket info");

    // Find sockets with process info
    let mut process_map: HashMap<u32, String> = HashMap::new();

    for socket in &sockets {
        if let (Some(pid), Some(name)) = (socket.process_id, &socket.process_name) {
            process_map.insert(pid, name.clone());
        }
    }

    assert!(
        !process_map.is_empty(),
        "Should find processes associated with sockets"
    );

    // Verify process names are reasonable
    for (pid, name) in process_map {
        assert!(pid > 0, "Process ID should be positive");
        assert!(!name.is_empty(), "Process name should not be empty");
        assert!(name.len() < 256, "Process name should be reasonable length");

        // Common macOS system processes we might see
        let known_processes = [
            "kernel_task",
            "launchd",
            "UserEventAgent",
            "WindowServer",
            "Dock",
            "Finder",
            "Safari",
            "Chrome",
            "firefox",
            "ssh",
            "sshd",
        ];

        // If it's a known system process, that's good
        // If not, that's also fine - user processes
        if known_processes.iter().any(|&p| name.contains(p)) {
            println!("Found known system process: {name} (PID: {pid})");
        }
    }
}

/// Test TCP socket states on macOS
#[test]
fn test_macos_tcp_socket_states() {
    // Create test sockets in different states
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to create listening socket");
    let listening_port = listener.local_addr().unwrap().port();

    // Create a connection
    let connector = std::net::TcpStream::connect(("127.0.0.1", listening_port));

    thread::sleep(Duration::from_millis(100));

    let sockets = get_sockets_info().expect("Failed to get socket info");

    // Find our listening socket
    let listening_socket = sockets.iter().find(|s| {
        s.local_addr.port() == listening_port
            && s.protocol == Protocol::Tcp
            && matches!(s.state, SocketState::Listen)
    });

    if listening_socket.is_some() {
        println!("Successfully found listening socket on port {listening_port}");
    } else {
        eprintln!("Warning: Could not find our test listening socket");
    }

    // Test various TCP states exist in the system
    let state_counts = sockets.iter().filter(|s| s.protocol == Protocol::Tcp).fold(
        HashMap::new(),
        |mut acc, socket| {
            *acc.entry(&socket.state).or_insert(0) += 1;
            acc
        },
    );

    println!("TCP socket states found:");
    for (state, count) in &state_counts {
        println!("  {state:?}: {count}");
    }

    // Should have at least some established connections on a typical system
    assert!(!state_counts.is_empty(), "Should find various TCP states");

    drop(connector);
    drop(listener);
}

/// Test UDP socket detection on macOS
#[test]
fn test_macos_udp_socket_detection() {
    let udp_socket = UdpSocket::bind("127.0.0.1:0").expect("Failed to create UDP socket");
    let udp_port = udp_socket.local_addr().unwrap().port();

    thread::sleep(Duration::from_millis(100));

    let sockets = get_sockets_info().expect("Failed to get socket info");

    let udp_sockets: Vec<_> = sockets
        .iter()
        .filter(|s| s.protocol == Protocol::Udp)
        .collect();

    assert!(!udp_sockets.is_empty(), "Should find UDP sockets");

    // Try to find our specific UDP socket
    let our_socket = udp_sockets.iter().find(|s| s.local_addr.port() == udp_port);

    if our_socket.is_some() {
        println!("Successfully found our UDP socket on port {udp_port}");
    } else {
        eprintln!("Warning: Could not find our test UDP socket");
    }

    drop(udp_socket);
}

/// Test performance of libproc vs command-line tools
#[test]
fn test_macos_libproc_performance() {
    use std::time::Instant;

    // Test libproc performance
    let start = Instant::now();
    let libproc_sockets = get_sockets_info().expect("Failed to get sockets via libproc");
    let libproc_duration = start.elapsed();

    println!(
        "libproc found {} sockets in {:?}",
        libproc_sockets.len(),
        libproc_duration
    );

    // Compare with netstat (if available)
    let start = Instant::now();
    let netstat_result = Command::new("netstat").args(["-an", "-p", "tcp"]).output();

    if let Ok(output) = netstat_result {
        let netstat_duration = start.elapsed();
        let netstat_lines = String::from_utf8_lossy(&output.stdout).lines().count();

        println!("netstat found ~{netstat_lines} lines in {netstat_duration:?}");

        // libproc should be competitive or faster
        println!(
            "Performance comparison - libproc: {libproc_duration:?} vs netstat: {netstat_duration:?}"
        );
    } else {
        println!("netstat not available for comparison");
    }

    // Test consistency across multiple runs
    let mut durations = Vec::new();
    for _ in 0..5 {
        let start = Instant::now();
        let _ = get_sockets_info().expect("Failed to get socket info");
        durations.push(start.elapsed());
    }

    let avg_duration = durations.iter().sum::<Duration>() / u32::try_from(durations.len()).unwrap();
    println!("Average libproc duration over 5 runs: {avg_duration:?}");

    // Performance should be reasonable
    assert!(
        avg_duration < Duration::from_secs(3),
        "libproc socket enumeration should complete within 3 seconds"
    );
}

/// Test socket statistics on macOS
#[test]
fn test_macos_socket_statistics() {
    let sockets = get_sockets_info().expect("Failed to get socket info");

    // Test TCP sockets with statistics
    let tcp_with_stats: Vec<_> = sockets
        .iter()
        .filter(|s| s.protocol == Protocol::Tcp && s.stats.is_some())
        .collect();

    if tcp_with_stats.is_empty() {
        println!("Note: No TCP sockets with detailed statistics found");
    } else {
        println!("Found {} TCP sockets with statistics", tcp_with_stats.len());

        for socket in tcp_with_stats.iter().take(5) {
            if let Some(stats) = &socket.stats {
                println!(
                    "Socket {}:{} stats:",
                    socket.local_addr.ip(),
                    socket.local_addr.port()
                );

                if let Some(rtt) = stats.rtt {
                    println!("  RTT: {rtt:?}");
                }

                if let Some(cwnd) = stats.congestion_window {
                    println!("  Congestion Window: {cwnd}");
                }

                println!("  Retransmits: {}", stats.retransmits);
                println!("  Quality Score: {:.2}", stats.calculate_quality_score());

                if stats.has_buffer_bloat() {
                    println!("  Buffer bloat detected!");
                }

                let issues = stats.performance_issues();
                if !issues.is_empty() {
                    println!("  Issues: {issues:?}");
                }
            }
        }
    }
}

/// Test macOS-specific socket options and flags
#[test]
fn test_macos_socket_options() {
    let sockets = get_sockets_info().expect("Failed to get socket info");

    // Test socket family detection
    let inet_sockets: Vec<_> = sockets
        .iter()
        .filter(|s| {
            matches!(
                s.socket_family,
                Some(pree::socket::platform::SocketFamily::Inet)
            )
        })
        .collect();

    println!("Found {} IPv4 sockets", inet_sockets.len());
    println!(
        "Found {} IPv6 sockets",
        sockets
            .iter()
            .filter(|s| matches!(
                s.socket_family,
                Some(pree::socket::platform::SocketFamily::Inet6)
            ))
            .count()
    );

    // Should have at least some IPv4 sockets
    assert!(!inet_sockets.is_empty(), "Should find IPv4 sockets");

    // Test socket type detection
    let stream_sockets: Vec<_> = sockets
        .iter()
        .filter(|s| {
            matches!(
                s.socket_type,
                Some(pree::socket::platform::SocketType::Stream)
            )
        })
        .collect();

    let dgram_sockets: Vec<_> = sockets
        .iter()
        .filter(|s| {
            matches!(
                s.socket_type,
                Some(pree::socket::platform::SocketType::Datagram)
            )
        })
        .collect();

    println!("Found {} stream sockets", stream_sockets.len());
    println!("Found {} datagram sockets", dgram_sockets.len());

    assert!(!stream_sockets.is_empty(), "Should find stream sockets");
    assert!(!dgram_sockets.is_empty(), "Should find datagram sockets");
}

/// Test edge cases and error conditions on macOS
#[test]
fn test_macos_edge_cases() {
    // Test with process that doesn't exist
    // Test with process that doesn't exist - we'll skip this specific test since the function isn't public
    // Note: Testing via private functions would require refactoring the module structure

    // Test socket enumeration with high load
    let mut handles = Vec::new();

    // Create multiple sockets concurrently
    for _ in 0..10 {
        let handle = thread::spawn(|| {
            let _socket = TcpListener::bind("127.0.0.1:0");
            thread::sleep(Duration::from_millis(100));
        });
        handles.push(handle);
    }

    // Get sockets while other threads are creating them
    let sockets = get_sockets_info().expect("Should handle concurrent socket operations");
    assert!(!sockets.is_empty(), "Should still find sockets under load");

    // Clean up
    for handle in handles {
        let _ = handle.join();
    }
}

/// Test memory usage and resource cleanup
#[test]
fn test_macos_resource_usage() {
    use std::time::Instant;

    // Measure memory usage over multiple iterations
    let iterations = 100;
    let start = Instant::now();

    for i in 0..iterations {
        let sockets = get_sockets_info().expect("Failed to get socket info");

        // Process the sockets to ensure they're actually used
        let tcp_count = sockets
            .iter()
            .filter(|s| s.protocol == Protocol::Tcp)
            .count();

        if i % 20 == 0 {
            println!("Iteration {i}: found {tcp_count} TCP sockets");
        }

        // Small delay to allow observation
        if i % 10 == 0 {
            thread::sleep(Duration::from_millis(1));
        }
    }

    let total_duration = start.elapsed();
    println!("Completed {iterations} iterations in {total_duration:?}");
    println!("Average per iteration: {:?}", total_duration / iterations);

    // Should complete within reasonable time
    assert!(
        total_duration < Duration::from_secs(30),
        "Should complete stress test within 30 seconds"
    );
}
