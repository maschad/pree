# Socket Information Retrieval with libproc

This document describes the integration of libproc for retrieving socket information on macOS and Linux platforms.

## Overview

The socket platform module has been updated to use libproc instead of command-line tools (netstat, lsof, ps) for retrieving socket information. This provides:

- **Better Performance**: Direct system calls instead of spawning processes
- **More Reliable**: No parsing of command output that might change between versions
- **More Information**: Access to internal socket structures and statistics
- **Cross-Platform**: Unified approach for macOS and Linux

## Dependencies

### Core Dependencies
- `libproc = "0.14.10"` - Cross-platform process information library

### Optional Dependencies
- `procfs = "0.17.0"` - Linux-specific /proc filesystem interface (feature: `linux-procfs`)

## Platform Implementation

### macOS
Uses libproc's native macOS bindings:
- `libproc::file_info` - Enumerate file descriptors and get socket info
- `libproc::net_info` - Get detailed socket information
- `libproc::proc_pid` - Get process information
- `libproc::processes` - List all processes

### Linux
Two implementations available:

1. **With `linux-procfs` feature** (recommended):
   - Uses the `procfs` crate for cleaner API
   - Provides structured access to /proc/net/tcp, /proc/net/udp
   - Better type safety and error handling

2. **Without feature** (fallback):
   - Direct parsing of /proc filesystem
   - Compatible with systems where procfs crate might not work

### Windows
- Still uses command-line tools (netstat) with Windows API for extended stats
- TODO: Migrate to Windows API calls (GetTcpTable2, GetUdpTable, etc.)

## API Usage

```rust
use pree::socket::platform::{get_sockets_info, SocketInfo, SocketState};

// Get all sockets
let sockets = get_sockets_info()?;

for socket in sockets {
    println!("Socket: {} -> {}", socket.local_addr, socket.remote_addr);
    println!("  State: {:?}", socket.state);
    println!("  Protocol: {:?}", socket.protocol);
    
    if let Some(pid) = socket.process_id {
        println!("  Process: {} (PID: {})", 
            socket.process_name.as_deref().unwrap_or("Unknown"), 
            pid
        );
    }
    
    // TCP sockets have detailed statistics
    if let Some(stats) = &socket.stats {
        println!("  RTT: {:?}", stats.rtt);
        println!("  Congestion Window: {:?}", stats.congestion_window);
        println!("  Retransmits: {}", stats.retransmits);
        
        // Connection quality metrics
        let quality = stats.calculate_quality_score();
        println!("  Quality Score: {:.1}%", quality * 100.0);
        
        if stats.has_buffer_bloat() {
            println!("  Warning: Buffer bloat detected!");
        }
    }
}
```

## Socket Information Available

### Basic Information
- Local and remote addresses (IP:port)
- Socket state (Listen, Established, Closing, etc.)
- Protocol (TCP/UDP)
- Process ID and name
- Socket type (Stream, Datagram)
- Socket family (IPv4, IPv6)

### TCP Statistics (Limited on macOS)
- RTT (Round Trip Time)
- Congestion window
- Send/receive queue sizes
- Retransmission count
- MSS (Maximum Segment Size)
- Various TCP sequence numbers

### Connection Quality Metrics
- Quality score (0.0 to 1.0)
- Packet loss rate
- Buffer bloat detection
- Performance issue detection
- Bandwidth utilization
- Connection efficiency

## Building and Testing

### Enable all features
```bash
cargo build --all-features
```

### Run the example
```bash
cargo run --example socket_info_libproc --features socket-tracking
```

### Linux with procfs support
```bash
cargo run --features "socket-tracking linux-procfs"
```

## Limitations

### macOS
- libproc on macOS doesn't provide as detailed TCP statistics as Linux
- Some metrics like congestion control algorithm are not available
- Requires appropriate permissions to access other processes' information

### Linux  
- Without procfs feature, parsing is more fragile
- Some advanced TCP metrics require root access
- /proc filesystem must be mounted

### Windows
- Still uses command-line parsing (not yet migrated to libproc)
- Limited statistics available through netstat

## Future Improvements

1. **Windows Native API**: Implement using Windows IP Helper API
2. **Enhanced Statistics**: Add support for TCP_INFO socket option where available
3. **Unix Domain Sockets**: Add support for local/unix sockets
4. **Performance Monitoring**: Real-time socket performance tracking
5. **Historical Data**: Track socket state changes over time

## Example Output

```
=== Socket Information using libproc ===

Found 127 sockets

TCP Sockets (89):
Local Address             Remote Address            State           PID        Process
------------------------------------------------------------------------------------------
127.0.0.1:8080           0.0.0.0:0                Listen          1234       myapp
10.0.0.5:44566           52.84.228.25:443         Established     5678       chrome
127.0.0.1:5432           127.0.0.1:55234          Established     9012       postgres
  └─ Stats: RTT=Some(251µs), CWnd=Some(10), Retransmits=0
  └─ Quality: 100.0%, Packet Loss: 0.00%

UDP Sockets (38):
Local Address             Remote Address            PID        Process
----------------------------------------------------------------------
0.0.0.0:68               0.0.0.0:0                67         dhclient
127.0.0.1:53             0.0.0.0:0                123        systemd-resolved

Listening TCP Sockets:
  - 127.0.0.1:8080 (PID: 1234, Process: myapp)
  - 0.0.0.0:22 (PID: 456, Process: sshd)
  - 127.0.0.1:5432 (PID: 9012, Process: postgres)