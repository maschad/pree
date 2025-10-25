# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Pree is a cross-platform Rust library for network diagnostics and monitoring. It provides a unified API for accessing network information across Linux, macOS, and Windows, including socket enumeration, traffic statistics, DNS resolution, routing tables, and interface monitoring.

## Development Commands

### Building
```bash
# Standard build
cargo build

# Build with all features
cargo build --all-features

# Build with specific features
cargo build --features "socket-tracking dns-cache"

# Check compilation without building
cargo check
```

### Testing
```bash
# Run all tests
cargo test --verbose

# Run tests with all features
cargo test --all-features

# Run a specific test
cargo test test_name

# Run tests in a specific file
cargo test --test socket_discovery
```

### Linting and Formatting
```bash
# Check code formatting
cargo fmt --all -- --check

# Format code
cargo fmt --all

# Run clippy with project standards
cargo clippy \
  --all-targets \
  -- -D warnings \
  -W clippy::pedantic \
  -W clippy::nursery \
  -W clippy::style \
  -W clippy::complexity \
  -W clippy::perf \
  -W clippy::suspicious \
  -W clippy::correctness
```

### Benchmarks
```bash
# Run all benchmarks
cargo bench --all-features

# Run specific benchmark
cargo bench socket_performance
```

### Examples
```bash
# Run examples (require specific features)
cargo run --example interface_stats
cargo run --example bandwidth_monitor
cargo run --example routing_table
cargo run --example dns_config --features dns-cache
cargo run --example socket_monitor --features socket-tracking
cargo run --example port_checker --features socket-tracking
cargo run --example socket_info_libproc --features socket-tracking
```

## Architecture

### Module Structure

The codebase is organized into several core modules:

- **socket/**: Socket enumeration and monitoring
  - `platform.rs`: Platform-specific socket information retrieval (uses libproc on macOS, procfs on Linux)
  - `tcp.rs`: TCP socket management
  - `udp.rs`: UDP socket management
  - `monitor.rs`: Real-time socket monitoring with event callbacks
  - `socket.rs`: Core socket types and utilities

- **interface/**: Network interface discovery and monitoring
  - `mod.rs`: Interface listing and statistics
  - `monitor.rs`: Interface change detection
  - `nat.rs`: NAT detection and public IP discovery

- **routing.rs**: Routing table access and monitoring

- **dns/**: DNS resolution and caching
  - `resolver.rs`: DNS query functionality
  - `cache.rs`: TTL-based DNS record caching

- **platform.rs**: Platform abstraction layer
- **unix.rs**: Unix-specific implementations (macOS, Linux)
- **windows.rs**: Windows-specific implementations
- **types.rs**: Core types (SocketState, ProcessInfo, Protocol, etc.)
- **error.rs**: Error types and Result definitions

### Platform-Specific Implementation

The library uses conditional compilation to provide platform-specific implementations:

1. **macOS**: Uses `libproc` crate for direct access to kernel socket information via `libproc::file_info` and `libproc::net_info`. This provides better performance and reliability than parsing command-line tools.

2. **Linux**: Two approaches available:
   - With `linux-procfs` feature: Uses `procfs` crate for structured access to `/proc/net/tcp` and `/proc/net/udp`
   - Without feature: Direct parsing of `/proc` filesystem files

3. **Windows**: Uses WinAPI through the `winapi` crate. Socket information is currently retrieved via netstat parsing, but migration to Windows IP Helper API is planned.

### Key Design Patterns

- **Feature flags**: Optional functionality is gated behind Cargo features (`socket-tracking`, `dns-cache`, `async`, `serde-support`, `nat-detection`, `linux-procfs`)
- **Error handling**: Unified error types via `NetworkError` and `NetworkResult<T>`
- **Platform abstraction**: Platform-specific code is isolated behind common APIs
- **Zero-copy where possible**: Direct system calls avoid spawning processes
- **Event-driven monitoring**: Monitor types use callbacks for change detection

## Feature Flags

- `socket-tracking`: Enable process-level socket tracking with `libproc`
- `dns-cache`: Enable DNS record caching with TTL support
- `async`: Enable async/await support (tokio)
- `serde-support`: Enable serialization/deserialization via serde
- `nat-detection`: Enable NAT detection features
- `linux-procfs`: Use procfs crate on Linux (cleaner API, recommended)

## Important Implementation Notes

### Socket Information with libproc

The socket platform module uses `libproc` instead of command-line tools for better performance and reliability. See `SOCKET_LIBPROC_INTEGRATION.md` for detailed documentation on:
- How libproc is integrated on macOS and Linux
- Available socket statistics and metrics
- Connection quality scoring
- Platform-specific limitations

### macOS Considerations

- `libproc` on macOS provides less detailed TCP statistics than Linux
- Some metrics (congestion control algorithm) are not available
- Requires appropriate permissions to access other processes' information

### Testing Strategy

Tests are organized into:
- `tests/integration/`: Integration tests
- `tests/platform/`: Platform-specific test modules
- `tests/socket_discovery.rs`: Socket discovery tests
- `tests/linux_tests.rs`: Linux-specific tests
- `tests/macos_tests.rs`: macOS-specific tests

Platform-specific tests use conditional compilation to run only on the appropriate OS.

### Code Style

The project uses Rust 2024 edition and follows these conventions:
- Format with `rustfmt` using 2024 edition settings
- Allow specific clippy lints where justified (see `#[allow(clippy::...)]` annotations)
- Use `#[must_use]` on getter methods and important types
- Prefer `const fn` for simple constructors
- Use descriptive error types with `thiserror`

## Common Workflows

### Adding a New Platform-Specific Feature

1. Define the common API in the appropriate module (e.g., `socket/mod.rs`)
2. Implement platform-specific code in `unix.rs` or `windows.rs`
3. Use conditional compilation (`#[cfg(target_os = "...")]`)
4. Add platform-specific tests
5. Update examples if the feature is user-facing

### Adding Socket Statistics

Socket statistics are defined in `socket/platform.rs` with the `SocketStats` type. When adding new metrics:
1. Add fields to `SocketStats`
2. Update platform-specific parsing in `get_sockets_info()`
3. Update quality scoring in `calculate_quality_score()` if relevant
4. Add tests for the new metrics

### Monitoring Network Changes

The library provides monitor types (`InterfaceMonitor`, `SocketMonitor`) that use callbacks for change detection:
1. Create a monitor instance
2. Register callbacks with `on_*_change()` methods
3. Call `start()` to begin monitoring
4. Monitors poll at configurable intervals and emit events on changes
