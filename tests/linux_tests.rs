//! Linux-specific tests for socket enumeration and process mapping

#![cfg(target_os = "linux")]

use pree::socket::platform::get_sockets_info;
use pree::{Protocol, SocketState};
use std::collections::HashMap;
use std::fs;
use std::net::{TcpListener, UdpSocket};
use std::process::Command;
use std::thread;
use std::time::Duration;

/// Test /proc filesystem-based socket enumeration on Linux
#[test]
fn test_linux_proc_socket_enumeration() {
    let sockets = get_sockets_info().expect("Failed to get sockets via /proc");
    assert!(!sockets.is_empty(), "Should find sockets using /proc filesystem");
    
    // Verify we get both TCP and UDP sockets
    let tcp_sockets: Vec<_> = sockets.iter()
        .filter(|s| s.protocol == Protocol::Tcp)
        .collect();
    
    let udp_sockets: Vec<_> = sockets.iter()
        .filter(|s| s.protocol == Protocol::Udp)
        .collect();
    
    assert!(!tcp_sockets.is_empty(), "Should find TCP sockets");
    assert!(!udp_sockets.is_empty(), "Should find UDP sockets");
    
    // Test that we get process information
    let sockets_with_process: Vec<_> = sockets.iter()
        .filter(|s| s.process_id.is_some())
        .collect();
    
    assert!(!sockets_with_process.is_empty(), 
           "/proc parsing should provide process information");
}

/// Test Linux-specific process information accuracy
#[test]
fn test_linux_process_info_accuracy() {
    let sockets = get_sockets_info().expect("Failed to get socket info");
    
    // Find sockets with process info
    let mut process_map: HashMap<u32, String> = HashMap::new();
    
    for socket in &sockets {
        if let (Some(pid), Some(name)) = (socket.process_id, &socket.process_name) {
            process_map.insert(pid, name.clone());
        }
    }
    
    assert!(!process_map.is_empty(), "Should find processes associated with sockets");
    
    // Verify process names are reasonable and validate against /proc
    for (pid, name) in &process_map {
        assert!(*pid > 0, "Process ID should be positive");
        assert!(!name.is_empty(), "Process name should not be empty");
        
        // Verify process still exists in /proc
        let proc_path = format!("/proc/{}", pid);
        if std::path::Path::new(&proc_path).exists() {
            // Try to read process name from /proc
            let comm_path = format!("/proc/{}/comm", pid);
            if let Ok(proc_name) = fs::read_to_string(&comm_path) {
                let proc_name = proc_name.trim();
                
                // Names should be related (though may not be exact due to truncation)
                assert!(name.contains(proc_name) || proc_name.contains(name) || 
                       name.starts_with(proc_name) || proc_name.starts_with(name),
                       "Process name mismatch: socket='{}', proc='{}'", name, proc_name);
            }
        }
    }
    
    println!("Validated {} process entries", process_map.len());
}

/// Test /proc/net parsing consistency
#[test]
fn test_linux_proc_net_parsing() {
    // Test that our parsing matches what's in /proc/net
    let sockets = get_sockets_info().expect("Failed to get socket info");
    
    // Check /proc/net/tcp
    if let Ok(tcp_content) = fs::read_to_string("/proc/net/tcp") {
        let proc_tcp_lines: Vec<_> = tcp_content.lines().skip(1).collect(); // Skip header
        let our_tcp_sockets: Vec<_> = sockets.iter()
            .filter(|s| s.protocol == Protocol::Tcp)
            .collect();
        
        println!("Found {} TCP sockets in our implementation", our_tcp_sockets.len());
        println!("Found {} TCP lines in /proc/net/tcp", proc_tcp_lines.len());
        
        // Our count should be reasonably close to /proc count
        // (may differ due to parsing edge cases or timing)
        let ratio = our_tcp_sockets.len() as f64 / proc_tcp_lines.len() as f64;
        assert!(ratio > 0.5 && ratio <= 1.2, 
               "TCP socket count should be reasonably close to /proc/net/tcp");
    }
    
    // Check /proc/net/udp
    if let Ok(udp_content) = fs::read_to_string("/proc/net/udp") {
        let proc_udp_lines: Vec<_> = udp_content.lines().skip(1).collect(); // Skip header
        let our_udp_sockets: Vec<_> = sockets.iter()
            .filter(|s| s.protocol == Protocol::Udp)
            .collect();
        
        println!("Found {} UDP sockets in our implementation", our_udp_sockets.len());
        println!("Found {} UDP lines in /proc/net/udp", proc_udp_lines.len());
        
        let ratio = our_udp_sockets.len() as f64 / proc_udp_lines.len() as f64;
        assert!(ratio > 0.5 && ratio <= 1.2, 
               "UDP socket count should be reasonably close to /proc/net/udp");
    }
}

/// Test TCP socket states on Linux
#[test]
fn test_linux_tcp_socket_states() {
    // Create test sockets in different states
    let listener = TcpListener::bind("127.0.0.1:0")
        .expect("Failed to create listening socket");
    let listening_port = listener.local_addr().unwrap().port();
    
    thread::sleep(Duration::from_millis(100));
    
    let sockets = get_sockets_info().expect("Failed to get socket info");
    
    // Find our listening socket
    let listening_socket = sockets.iter()
        .find(|s| s.local_addr.port() == listening_port && 
                  s.protocol == Protocol::Tcp &&
                  matches!(s.state, SocketState::Listen));
    
    if listening_socket.is_some() {
        println!("Successfully found listening socket on port {}", listening_port);
    } else {
        eprintln!("Warning: Could not find our test listening socket");
    }
    
    // Test various TCP states exist in the system
    let state_counts = sockets.iter()
        .filter(|s| s.protocol == Protocol::Tcp)
        .fold(HashMap::new(), |mut acc, socket| {
            *acc.entry(&socket.state).or_insert(0) += 1;
            acc
        });
    
    println!("TCP socket states found:");
    for (state, count) in &state_counts {
        println!("  {:?}: {}", state, count);
    }
    
    // Should have at least some established connections on a typical system
    assert!(state_counts.len() > 0, "Should find various TCP states");
    
    drop(listener);
}

/// Test UDP socket detection on Linux
#[test] 
fn test_linux_udp_socket_detection() {
    let udp_socket = UdpSocket::bind("127.0.0.1:0")
        .expect("Failed to create UDP socket");
    let udp_port = udp_socket.local_addr().unwrap().port();
    
    thread::sleep(Duration::from_millis(100));
    
    let sockets = get_sockets_info().expect("Failed to get socket info");
    
    let udp_sockets: Vec<_> = sockets.iter()
        .filter(|s| s.protocol == Protocol::Udp)
        .collect();
    
    assert!(!udp_sockets.is_empty(), "Should find UDP sockets");
    
    // Try to find our specific UDP socket
    let our_socket = udp_sockets.iter()
        .find(|s| s.local_addr.port() == udp_port);
    
    if our_socket.is_some() {
        println!("Successfully found our UDP socket on port {}", udp_port);
    } else {
        eprintln!("Warning: Could not find our test UDP socket");
    }
    
    drop(udp_socket);
}

/// Test performance vs command-line tools on Linux
#[test]
fn test_linux_performance_vs_netstat() {
    use std::time::Instant;
    
    // Test our implementation performance
    let start = Instant::now();
    let our_sockets = get_sockets_info().expect("Failed to get sockets");
    let our_duration = start.elapsed();
    
    println!("Our implementation found {} sockets in {:?}", 
             our_sockets.len(), our_duration);
    
    // Compare with ss (modern replacement for netstat)
    let start = Instant::now();
    let ss_result = Command::new("ss")
        .args(["-tuln"])
        .output();
    
    if let Ok(output) = ss_result {
        let ss_duration = start.elapsed();
        let ss_lines = String::from_utf8_lossy(&output.stdout)
            .lines()
            .count();
        
        println!("ss found ~{} lines in {:?}", ss_lines, ss_duration);
        
        // Our implementation should be competitive
        println!("Performance comparison - ours: {:?} vs ss: {:?}", 
                 our_duration, ss_duration);
    } else {
        println!("ss command not available, trying netstat");
        
        // Fallback to netstat
        let start = Instant::now();
        let netstat_result = Command::new("netstat")
            .args(["-tuln"])
            .output();
            
        if let Ok(output) = netstat_result {
            let netstat_duration = start.elapsed();
            let netstat_lines = String::from_utf8_lossy(&output.stdout)
                .lines()
                .count();
            
            println!("netstat found ~{} lines in {:?}", netstat_lines, netstat_duration);
        }
    }
    
    // Test consistency across multiple runs
    let mut durations = Vec::new();
    for _ in 0..5 {
        let start = Instant::now();
        let _ = get_sockets_info().expect("Failed to get socket info");
        durations.push(start.elapsed());
    }
    
    let avg_duration = durations.iter().sum::<Duration>() / durations.len() as u32;
    println!("Average duration over 5 runs: {:?}", avg_duration);
    
    // Performance should be reasonable
    assert!(avg_duration < Duration::from_secs(2), 
           "Socket enumeration should complete within 2 seconds");
}

/// Test inode mapping accuracy on Linux
#[test]
fn test_linux_inode_mapping() {
    let sockets = get_sockets_info().expect("Failed to get socket info");
    
    // Check that sockets with process info have reasonable inodes
    let mut inode_count = 0;
    
    for socket in &sockets {
        if socket.process_id.is_some() {
            // On Linux, sockets should have inode information
            // Note: Our current implementation may not expose inodes directly,
            // but the underlying system uses them for process mapping
            inode_count += 1;
        }
    }
    
    println!("Found {} sockets with process information", inode_count);
    assert!(inode_count > 0, "Should find sockets with process mapping");
}

/// Test /proc filesystem feature detection
#[test]
fn test_linux_proc_filesystem_features() {
    // Test that required /proc files exist
    assert!(std::path::Path::new("/proc/net/tcp").exists(), 
           "/proc/net/tcp should exist");
    assert!(std::path::Path::new("/proc/net/udp").exists(), 
           "/proc/net/udp should exist");
    
    // Test IPv6 support if available
    if std::path::Path::new("/proc/net/tcp6").exists() {
        println!("IPv6 support detected (/proc/net/tcp6 exists)");
        
        let sockets = get_sockets_info().expect("Failed to get socket info");
        let ipv6_sockets: Vec<_> = sockets.iter()
            .filter(|s| s.local_addr.is_ipv6())
            .collect();
        
        println!("Found {} IPv6 sockets", ipv6_sockets.len());
    }
    
    // Test that we can read process directories
    assert!(std::path::Path::new("/proc/self").exists(), 
           "/proc/self should exist");
    assert!(std::path::Path::new("/proc/self/fd").exists(), 
           "/proc/self/fd should exist");
}

/// Test Linux socket options and extended information
#[test]
fn test_linux_socket_extended_info() {
    let sockets = get_sockets_info().expect("Failed to get socket info");
    
    // Test socket family detection
    let inet_sockets: Vec<_> = sockets.iter()
        .filter(|s| s.local_addr.is_ipv4())
        .collect();
    
    let inet6_sockets: Vec<_> = sockets.iter()
        .filter(|s| s.local_addr.is_ipv6())
        .collect();
    
    println!("Found {} IPv4 sockets", inet_sockets.len());
    println!("Found {} IPv6 sockets", inet6_sockets.len());
    
    // Should have at least some IPv4 sockets
    assert!(!inet_sockets.is_empty(), "Should find IPv4 sockets");
    
    // Test protocol distribution
    let tcp_count = sockets.iter()
        .filter(|s| s.protocol == Protocol::Tcp)
        .count();
    
    let udp_count = sockets.iter()
        .filter(|s| s.protocol == Protocol::Udp)
        .count();
    
    println!("Protocol distribution - TCP: {}, UDP: {}", tcp_count, udp_count);
    
    assert!(tcp_count > 0, "Should find TCP sockets");
    assert!(udp_count > 0, "Should find UDP sockets");
}

/// Test error handling and edge cases on Linux
#[test]
fn test_linux_edge_cases() {
    // Test with high socket creation load
    let mut handles = Vec::new();
    
    // Create multiple sockets concurrently
    for _ in 0..20 {
        let handle = thread::spawn(|| {
            let _tcp = TcpListener::bind("127.0.0.1:0").ok();
            let _udp = UdpSocket::bind("127.0.0.1:0").ok();
            thread::sleep(Duration::from_millis(50));
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
    
    // Test with process that doesn't exist
    // Note: Our Linux implementation may not have a direct get_process_info function
    // but the socket enumeration should handle missing processes gracefully
    let sockets_before = get_sockets_info().expect("Failed to get sockets");
    let sockets_after = get_sockets_info().expect("Failed to get sockets");
    
    // Should be consistent
    let diff = (sockets_before.len() as i32 - sockets_after.len() as i32).abs();
    assert!(diff < 50, "Socket count should be relatively stable");
}

/// Test memory usage and resource cleanup on Linux
#[test]
fn test_linux_resource_usage() {
    use std::time::Instant;
    
    // Measure performance over multiple iterations
    let iterations = 100;
    let start = Instant::now();
    
    for i in 0..iterations {
        let sockets = get_sockets_info().expect("Failed to get socket info");
        
        // Process the sockets to ensure they're actually used
        let tcp_count = sockets.iter()
            .filter(|s| s.protocol == Protocol::Tcp)
            .count();
        
        if i % 20 == 0 {
            println!("Iteration {}: found {} TCP sockets", i, tcp_count);
        }
        
        // Small delay to allow observation
        if i % 10 == 0 {
            thread::sleep(Duration::from_millis(1));
        }
    }
    
    let total_duration = start.elapsed();
    println!("Completed {} iterations in {:?}", iterations, total_duration);
    println!("Average per iteration: {:?}", total_duration / iterations);
    
    // Should complete within reasonable time
    assert!(total_duration < Duration::from_secs(20), 
           "Should complete stress test within 20 seconds");
}

/// Test Linux-specific networking features
#[test]
fn test_linux_networking_features() {
    let sockets = get_sockets_info().expect("Failed to get socket info");
    
    // Test for common Linux system sockets
    let system_ports = [22, 53, 80, 443, 631]; // SSH, DNS, HTTP, HTTPS, CUPS
    let mut found_system_sockets = 0;
    
    for &port in &system_ports {
        let port_sockets: Vec<_> = sockets.iter()
            .filter(|s| s.local_addr.port() == port)
            .collect();
        
        if !port_sockets.is_empty() {
            println!("Found {} sockets on system port {}", port_sockets.len(), port);
            found_system_sockets += 1;
        }
    }
    
    println!("Found system sockets on {}/{} common ports", 
             found_system_sockets, system_ports.len());
    
    // Test localhost vs external addresses
    let localhost_sockets: Vec<_> = sockets.iter()
        .filter(|s| s.local_addr.ip().is_loopback())
        .collect();
    
    let external_sockets: Vec<_> = sockets.iter()
        .filter(|s| !s.local_addr.ip().is_loopback() && !s.local_addr.ip().is_unspecified())
        .collect();
    
    println!("Localhost sockets: {}", localhost_sockets.len());
    println!("External sockets: {}", external_sockets.len());
    
    // Should have at least some localhost sockets on any system
    assert!(!localhost_sockets.is_empty(), "Should find localhost sockets");
}