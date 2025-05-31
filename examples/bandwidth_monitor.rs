use pree::interface::Interface;
use std::thread;
use std::time::Duration;

fn main() -> pree::Result<()> {
    // Get initial stats for all interfaces
    let interfaces = Interface::list()?;
    let mut previous_stats = std::collections::HashMap::new();

    for iface in &interfaces {
        previous_stats.insert(iface.name.clone(), iface.stats.clone());
    }

    // Monitor bandwidth for 30 seconds
    for _ in 0..30 {
        thread::sleep(Duration::from_secs(1));

        let interfaces = Interface::list()?;
        for iface in &interfaces {
            if let Some(prev_stats) = previous_stats.get(&iface.name) {
                let rx_bytes_delta = iface.stats.rx_bytes - prev_stats.rx_bytes;
                let tx_bytes_delta = iface.stats.tx_bytes - prev_stats.tx_bytes;

                // Convert to Mbps (megabits per second)
                let rx_mbps = (rx_bytes_delta * 8) / 1_000_000;
                let tx_mbps = (tx_bytes_delta * 8) / 1_000_000;

                println!("\nInterface: {}", iface.name);
                println!("  Download: {rx_mbps} Mbps");
                println!("  Upload: {tx_mbps} Mbps");
            }
            previous_stats.insert(iface.name.clone(), iface.stats.clone());
        }
    }

    Ok(())
}
