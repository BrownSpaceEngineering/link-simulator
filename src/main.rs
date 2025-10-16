use clap::Parser;
use link_sim::Link;
use std::{net::IpAddr, process::Command};

#[derive(Parser, Debug)]
#[command(name = "link-sim")]
struct Args {
    /// Path to the space binary executable
    #[arg(long)]
    space_binary: String,

    /// Port for the space side to connect to the simulator
    #[arg(long)]
    space_port: u16,

    /// Path to the ground binary executable
    #[arg(long)]
    ground_binary: String,

    /// Port for the ground side to connect to the simulator
    #[arg(long)]
    ground_port: u16,

    /// Link delay in milliseconds
    #[arg(long, default_value = "100")]
    delay_ms: u32,

    /// Bit error rate (0 -> 1.0)
    #[arg(long, default_value = "0.0")]
    bit_error_rate: f64,

    // NOTE: Haven't implemented this yet but stubbing it here
    /// Maximum bandwidth in bytes/second
    #[arg(long, default_value = "1000000")]
    max_bandwidth: f64,

    /// IP if different
    #[arg(long, default_value = "127.0.0.1")]
    ip: String,
    // NOTE:
    // THINGS I'D LIKE TO IMPLEMENT
    // - half-full-duplex (Bool) - Determines if channel is half-duplex (cannot simultaneously transmit/receive)
    //                             or full duplex (constant bidirectional). If half duplex, introduce delay between send/recv
    // - Doppler Shift
    // - Free space path loss
    // - Line losses(?) could simulate a full componentized GS, but that would be another project
    // hooked into this one
    // - Atmospheric scattering (scary)
}

fn main() {
    let args = Args::parse();

    // Parse IP address
    let ip: IpAddr = args.ip.parse().expect("Invalid IP address");

    println!("Starting simulator with parameters:");
    println!("Delay (ms): {}", args.delay_ms);
    println!("Bit error rate: {}", args.bit_error_rate);
    println!("Max channel bandwidth: {}", args.max_bandwidth);
    println!();

    println!("Launching space binary...");
    let mut space_process = Command::new(&args.space_binary)
        .arg("--port")
        .arg(args.space_port.to_string())
        .spawn()
        .expect("Failed to launch space binary");

    println!("Launching ground binary...");
    let mut ground_process = Command::new(&args.ground_binary)
        .arg("--port")
        .arg(args.ground_port.to_string())
        .spawn()
        .expect("Failed to launch ground binary");
    std::thread::sleep(std::time::Duration::from_millis(500));

    let mut link = Link::new(
        args.bit_error_rate,
        args.delay_ms,
        args.max_bandwidth,
        ip,
        (args.space_port, "Space".to_string()),
        (args.ground_port, "Ground".to_string()),
    );

    if let Err(e) = link.run() {
        eprintln!("Link simulator error: {}", e);
    }
    // Clean up child processes
    let _ = space_process.kill();
    let _ = ground_process.kill();
}
