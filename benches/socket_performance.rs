//! Performance benchmarks for socket enumeration across platforms

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pree::socket::platform::get_sockets_info;
use pree::socket::socket::{Socket, SocketConfig};
use pree::{Protocol, SocketState, TcpSocket, UdpSocket};
use std::net::{TcpListener, UdpSocket as StdUdpSocket};
use std::thread;
use std::time::Duration;

/// Benchmark basic socket enumeration
fn bench_socket_enumeration(c: &mut Criterion) {
    c.bench_function("socket_enumeration", |b| {
        b.iter(|| {
            let sockets = get_sockets_info().expect("Failed to get socket info");
            black_box(sockets)
        });
    });
}

/// Benchmark socket enumeration with filtering
fn bench_socket_filtering(c: &mut Criterion) {
    c.bench_function("socket_filtering", |b| {
        b.iter(|| {
            let sockets = get_sockets_info().expect("Failed to get socket info");
            let tcp_sockets: Vec<_> = sockets
                .into_iter()
                .filter(|s| s.protocol == Protocol::Tcp)
                .collect();
            black_box(tcp_sockets)
        });
    });
}

/// Benchmark TCP socket counting
fn bench_tcp_socket_count(c: &mut Criterion) {
    c.bench_function("tcp_socket_count", |b| {
        b.iter(|| {
            let count = TcpSocket::count_active().expect("Failed to count TCP sockets");
            black_box(count)
        });
    });
}

/// Benchmark UDP socket counting
fn bench_udp_socket_count(c: &mut Criterion) {
    c.bench_function("udp_socket_count", |b| {
        b.iter(|| {
            let count = UdpSocket::count_active().expect("Failed to count UDP sockets");
            black_box(count)
        });
    });
}

/// Benchmark generic socket listing
fn bench_generic_socket_list(c: &mut Criterion) {
    c.bench_function("generic_socket_list", |b| {
        b.iter(|| {
            let sockets = Socket::list().expect("Failed to list sockets");
            black_box(sockets)
        });
    });
}

/// Benchmark socket enumeration with load
fn bench_socket_enumeration_under_load(c: &mut Criterion) {
    // Create some test sockets to add load
    let _listeners: Vec<_> = (0..10)
        .map(|_| TcpListener::bind("127.0.0.1:0").ok())
        .collect();

    let _udp_sockets: Vec<_> = (0..10)
        .map(|_| StdUdpSocket::bind("127.0.0.1:0").ok())
        .collect();

    thread::sleep(Duration::from_millis(100)); // Let sockets settle

    c.bench_function("socket_enumeration_under_load", |b| {
        b.iter(|| {
            let sockets = get_sockets_info().expect("Failed to get socket info");
            black_box(sockets)
        });
    });
}

/// Benchmark process information retrieval
fn bench_process_info_retrieval(c: &mut Criterion) {
    c.bench_function("process_info_retrieval", |b| {
        b.iter(|| {
            let sockets = get_sockets_info().expect("Failed to get socket info");
            let with_process: Vec<_> = sockets
                .into_iter()
                .filter(|s| s.process_id.is_some())
                .collect();
            black_box(with_process)
        });
    });
}

/// Benchmark socket state analysis
fn bench_socket_state_analysis(c: &mut Criterion) {
    c.bench_function("socket_state_analysis", |b| {
        b.iter(|| {
            let sockets = get_sockets_info().expect("Failed to get socket info");
            let mut state_counts = std::collections::HashMap::new();

            for socket in sockets {
                *state_counts.entry(socket.state).or_insert(0) += 1;
            }

            black_box(state_counts)
        });
    });
}

/// Benchmark concurrent socket enumeration
fn bench_concurrent_socket_enumeration(c: &mut Criterion) {
    c.bench_function("concurrent_socket_enumeration", |b| {
        b.iter(|| {
            let handles: Vec<_> = (0..4)
                .map(|_| thread::spawn(|| get_sockets_info().expect("Failed to get socket info")))
                .collect();

            let mut results = Vec::new();
            for handle in handles {
                results.push(handle.join().unwrap());
            }

            black_box(results)
        });
    });
}

/// Platform-specific benchmarks
#[cfg(target_os = "macos")]
fn bench_macos_libproc(c: &mut Criterion) {
    c.bench_function("macos_libproc_enumeration", |b| {
        b.iter(|| {
            let sockets = get_sockets_info().expect("Failed to get socket info");
            black_box(sockets);
        });
    });
}

#[cfg(target_os = "linux")]
fn bench_linux_proc_parsing(c: &mut Criterion) {
    use std::fs;

    c.bench_function("linux_proc_file_reading", |b| {
        b.iter(|| {
            let tcp_content = fs::read_to_string("/proc/net/tcp").ok();
            let udp_content = fs::read_to_string("/proc/net/udp").ok();
            black_box((tcp_content, udp_content))
        })
    });
}

/// Memory usage benchmark
fn bench_memory_usage(c: &mut Criterion) {
    c.bench_function("memory_usage_multiple_iterations", |b| {
        b.iter(|| {
            // Perform multiple socket enumerations to test memory usage
            for _ in 0..10 {
                let sockets = get_sockets_info().expect("Failed to get socket info");
                // Process sockets to ensure they're not optimized away
                let count = sockets.len();
                black_box(count);
            }
        });
    });
}

/// Benchmark socket discovery with different filters
fn bench_socket_discovery_filters(c: &mut Criterion) {
    let mut group = c.benchmark_group("socket_filters");

    group.bench_function("filter_by_protocol", |b| {
        b.iter(|| {
            let sockets = get_sockets_info().expect("Failed to get socket info");
            let tcp_only: Vec<_> = sockets
                .into_iter()
                .filter(|s| s.protocol == Protocol::Tcp)
                .collect();
            black_box(tcp_only)
        });
    });

    group.bench_function("filter_by_state", |b| {
        b.iter(|| {
            let sockets = get_sockets_info().expect("Failed to get socket info");
            let listening_only: Vec<_> = sockets
                .into_iter()
                .filter(|s| matches!(s.state, SocketState::Listen))
                .collect();
            black_box(listening_only)
        });
    });

    group.bench_function("filter_by_process", |b| {
        b.iter(|| {
            let sockets = get_sockets_info().expect("Failed to get socket info");
            let with_process: Vec<_> = sockets
                .into_iter()
                .filter(|s| s.process_id.is_some())
                .collect();
            black_box(with_process)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_socket_enumeration,
    bench_socket_filtering,
    bench_tcp_socket_count,
    bench_udp_socket_count,
    bench_generic_socket_list,
    bench_socket_enumeration_under_load,
    bench_process_info_retrieval,
    bench_socket_state_analysis,
    bench_concurrent_socket_enumeration,
    bench_memory_usage,
    bench_socket_discovery_filters
);

#[cfg(target_os = "macos")]
criterion_group!(platform_benches, bench_macos_libproc);

#[cfg(target_os = "linux")]
criterion_group!(platform_benches, bench_linux_proc_parsing);

#[cfg(target_os = "macos")]
criterion_main!(benches, platform_benches);

#[cfg(target_os = "linux")]
criterion_main!(benches, platform_benches);

#[cfg(target_os = "windows")]
criterion_main!(benches);
