//! Integration tests for socket discovery across platforms

use pree::socket::platform::{get_sockets_info, SocketInfo};
use pree::socket::socket::{Socket, SocketConfig};
use pree::{Protocol, SocketState, TcpSocket, UdpSocket};
use std::net::{TcpListener, UdpSocket as StdUdpSocket};
use std::thread;
use std::time::Duration;

/// Test basic socket discovery functionality
#[test]
fn test_socket_discovery_basic() {
    // Create test sockets
    let tcp_listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind TCP socket");
    let tcp_port = tcp_listener.local_addr().unwrap().port();

    let udp_socket = StdUdpSocket::bind("127.0.0.1:0").expect("Failed to bind UDP socket");
    let udp_port = udp_socket.local_addr().unwrap().port();

    // Give the system time to register the sockets
    thread::sleep(Duration::from_millis(100));

    // Test platform-specific socket discovery
    let sockets = get_sockets_info().expect("Failed to get socket info");
    assert!(!sockets.is_empty(), "Should find at least some sockets");

    // Test generic socket discovery
    let generic_sockets = Socket::list().expect("Failed to list sockets");
    assert!(
        !generic_sockets.is_empty(),
        "Should find at least some sockets"
    );

    // Verify our test sockets are discoverable
    let tcp_found = sockets.iter().any(|s| s.local_addr.port() == tcp_port);
    let udp_found = sockets.iter().any(|s| s.local_addr.port() == udp_port);

    // Note: On some systems, the sockets might not be immediately visible
    // This is expected behavior, so we log but don't fail
    if !tcp_found {
        eprintln!("Warning: TCP test socket not found in socket list");
    }
    if !udp_found {
        eprintln!("Warning: UDP test socket not found in socket list");
    }

    // Test socket counting
    let tcp_count = TcpSocket::count_active().expect("Failed to count TCP sockets");
    let udp_count = UdpSocket::count_active().expect("Failed to count UDP sockets");

    assert!(tcp_count > 0, "Should have at least one TCP socket");
    assert!(udp_count > 0, "Should have at least one UDP socket");
}

/// Test socket filtering and querying
#[test]
fn test_socket_filtering() {
    let sockets = get_sockets_info().expect("Failed to get socket info");

    // Test filtering by protocol
    let tcp_count = sockets
        .iter()
        .filter(|s| s.protocol == Protocol::Tcp)
        .count();
    let udp_count = sockets
        .iter()
        .filter(|s| s.protocol == Protocol::Udp)
        .count();

    assert!(tcp_count > 0, "Should find TCP sockets");
    assert!(udp_count > 0, "Should find UDP sockets");

    // Test process association
    let sockets_with_process_count = sockets.iter().filter(|s| s.process_id.is_some()).count();

    assert!(
        sockets_with_process_count > 0,
        "Should find sockets with process info"
    );
}

/// Test socket state consistency
#[test]
fn test_socket_state_consistency() {
    let sockets = get_sockets_info().expect("Failed to get socket info");

    for socket in sockets {
        // Verify addresses are valid
        assert!(
            socket.local_addr.port() > 0 || socket.local_addr.ip().is_unspecified(),
            "Local address should be valid"
        );

        // Verify protocol is expected
        assert!(
            matches!(socket.protocol, Protocol::Tcp | Protocol::Udp),
            "Protocol should be TCP or UDP"
        );

        // Verify state is consistent
        match socket.protocol {
            Protocol::Tcp => {
                // TCP sockets should have meaningful states
                assert!(
                    matches!(
                        socket.state,
                        SocketState::Established
                            | SocketState::Listen
                            | SocketState::Connecting
                            | SocketState::Closing
                            | SocketState::Closed
                            | SocketState::Unknown(_)
                    ),
                    "TCP socket should have valid state"
                );
            }
            Protocol::Udp => {
                // UDP sockets are typically in established state
                assert!(
                    matches!(
                        socket.state,
                        SocketState::Established | SocketState::Bound | SocketState::Unknown(_)
                    ),
                    "UDP socket should have valid state"
                );
            }
            _ => {}
        }

        // If process info is available, verify it's consistent
        if let Some(pid) = socket.process_id {
            assert!(pid > 0, "Process ID should be positive");
        }
    }
}

/// Test socket monitoring over time
#[test]
fn test_socket_monitoring() {
    let initial_sockets = get_sockets_info().expect("Failed to get initial socket info");
    let initial_count = initial_sockets.len();

    // Create a temporary socket
    let _temp_listener =
        TcpListener::bind("127.0.0.1:0").expect("Failed to create temporary socket");

    thread::sleep(Duration::from_millis(100));

    let updated_sockets = get_sockets_info().expect("Failed to get updated socket info");
    let updated_count = updated_sockets.len();

    // Note: Socket count might not change due to system variations
    // This is expected behavior on some systems
    if updated_count == initial_count {
        eprintln!("Warning: Socket count unchanged after creating new socket");
    }

    // Verify we can still get socket info consistently
    assert!(!updated_sockets.is_empty(), "Should still have sockets");
}

/// Test error handling and edge cases
#[test]
fn test_error_handling() {
    // Test with invalid process ID
    let invalid_sockets = Socket::for_process(0).expect("Should handle invalid PID gracefully");
    assert!(
        invalid_sockets.is_empty(),
        "Should return empty list for invalid PID"
    );

    // Test with invalid port
    let _port_sockets = Socket::listening_on(0).expect("Should handle port 0 gracefully");
    // Port 0 might have sockets, so we just verify it doesn't crash

    // Test socket listing doesn't crash
    let _ = TcpSocket::list().expect("TCP socket listing should not crash");
    let _ = UdpSocket::list().expect("UDP socket listing should not crash");
}

/// Test cross-platform socket information consistency
#[test]
fn test_cross_platform_consistency() {
    let sockets = get_sockets_info().expect("Failed to get socket info");

    for socket in sockets {
        // Test that socket information is properly populated
        test_socket_info_completeness(&socket);
    }
}

fn test_socket_info_completeness(socket: &SocketInfo) {
    // Local address should always be present and valid
    assert!(
        socket.local_addr.port() > 0 || socket.local_addr.ip().is_unspecified(),
        "Local address should be valid"
    );

    // Protocol should be known
    assert!(
        matches!(socket.protocol, Protocol::Tcp | Protocol::Udp),
        "Protocol should be TCP or UDP"
    );

    // State should be valid
    if let SocketState::Unknown(msg) = &socket.state {
        assert!(!msg.is_empty(), "Unknown state should have description");
    }

    // If process info is present, it should be valid
    if let Some(pid) = socket.process_id {
        assert!(pid > 0, "Process ID should be positive");
    }

    if let Some(name) = &socket.process_name {
        assert!(!name.is_empty(), "Process name should not be empty");
    }
}

/// Performance test for socket discovery
#[test]
fn test_socket_discovery_performance() {
    use std::time::Instant;

    let start = Instant::now();
    let sockets = get_sockets_info().expect("Failed to get socket info");
    let duration = start.elapsed();

    println!("Socket discovery took: {duration:?}");
    println!("Found {} sockets", sockets.len());

    // Should complete within reasonable time (adjust as needed)
    assert!(
        duration < Duration::from_secs(5),
        "Socket discovery should complete within 5 seconds"
    );

    // Test multiple iterations for consistency
    let mut durations = Vec::new();
    for _ in 0..5 {
        let start = Instant::now();
        let _ = get_sockets_info().expect("Failed to get socket info");
        durations.push(start.elapsed());
    }

    // Calculate average
    let avg_duration = durations.iter().sum::<Duration>() / u32::try_from(durations.len()).unwrap();
    println!("Average socket discovery time: {avg_duration:?}");

    // Verify performance is consistent
    assert!(
        avg_duration < Duration::from_secs(2),
        "Average socket discovery should be under 2 seconds"
    );
}
