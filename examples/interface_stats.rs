use pree::interface::{Interface, InterfaceEvent, InterfaceMonitor};
use std::thread;
use std::time::Duration;

fn main() -> pree::Result<()> {
    // List all interfaces and their stats
    let interfaces = Interface::list()?;
    println!("Network Interfaces:");
    for iface in &interfaces {
        println!("\nInterface: {}", iface.name);
        println!("  Type: {:?}", iface.kind);
        println!("  Status: {}", if iface.is_up { "UP" } else { "DOWN" });
        println!("  MAC: {:?}", iface.mac_address);
        println!("  MTU: {}", iface.mtu);
        println!(
            "  IPs: {}",
            iface
                .ipv4
                .iter()
                .chain(iface.ipv6.iter())
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );

        // Get interface statistics
        println!("  RX Bytes: {}", iface.stats.rx_bytes);
        println!("  TX Bytes: {}", iface.stats.tx_bytes);
        println!("  RX Packets: {}", iface.stats.rx_packets);
        println!("  TX Packets: {}", iface.stats.tx_packets);
        println!("  RX Errors: {}", iface.stats.rx_errors);
        println!("  TX Errors: {}", iface.stats.tx_errors);
    }

    // Monitor interface changes
    let mut monitor = InterfaceMonitor::new()?;
    monitor.on_interface_change(|event| match event {
        InterfaceEvent::Added(iface) => {
            println!("\nNew interface detected: {}", iface.name);
        }
        InterfaceEvent::Removed(iface) => {
            println!("\nInterface removed: {}", iface.name);
        }
        InterfaceEvent::IpChanged(iface) => {
            println!(
                "\nIP changed for {}: {}",
                iface.name,
                iface
                    .ipv4
                    .iter()
                    .chain(iface.ipv6.iter())
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        InterfaceEvent::StatsChanged(iface, stats) => {
            println!("\nStats updated for {}:", iface.name);
            println!("  RX Bytes: {}", stats.rx_bytes);
            println!("  TX Bytes: {}", stats.tx_bytes);
            println!("  RX Packets: {}", stats.rx_packets);
            println!("  TX Packets: {}", stats.tx_packets);
        }
        _ => {}
    })?;

    // Start monitoring
    monitor.start()?;

    // Monitor for 30 seconds
    thread::sleep(Duration::from_secs(30));

    // Stop monitoring
    monitor.stop();

    Ok(())
}
