use std::{
    io,
    net::{IpAddr, SocketAddr, UdpSocket},
    process::exit,
    time::{Duration, Instant},
};

// Implements a 'Packet,' which isn't really a packet in the traditional sense,
// as it just has metadata we use for delivering it correctly.
pub struct Packet {
    pub bytes: Vec<u8>,
    pub length: u32,
    pub addr: SocketAddr,
    pub send_time: Instant,
    pub space_or_ground: bool,
}

impl Packet {
    pub fn new(
        bytes: Vec<u8>,
        length: u32,
        addr: SocketAddr,
        send_time: Instant,
        space_or_ground: bool,
    ) -> Packet {
        Packet {
            bytes,
            length,
            addr,
            send_time,
            space_or_ground,
        }
    }
}

// Type alias for loss functions
// Returns true to keep the packet, false to drop it
pub type LossFunction =
    Box<dyn Fn(&mut Packet, &mut dyn rand::RngCore, &mut LinkStatistics) -> bool>;

pub struct LossPipeline {
    pub functions: Vec<LossFunction>,
}

impl LossPipeline {
    pub fn new() -> Self {
        LossPipeline {
            functions: Vec::new(),
        }
    }

    pub fn process_packet(
        &self,
        packet: &mut Packet,
        rng: &mut dyn rand::RngCore,
        stats: &mut LinkStatistics,
    ) -> bool {
        for func in &self.functions {
            if !func(packet, rng, stats) {
                return false; // Packet was dropped by this function
            }
        }
        true // Packet passed through all functions
    }
}

pub struct Link {
    bit_error_rate: f64,
    delay_ms: u32,
    max_bandwidth: f64,
    space_side: UdpConn,
    ground_side: UdpConn,
    loss_pipeline: LossPipeline,
}

pub fn bit_error_function(bit_error_rate: f64) -> LossFunction {
    Box::new(
        move |packet: &mut Packet, rng: &mut dyn rand::RngCore, stats: &mut LinkStatistics| {
            use rand::Rng;
            if bit_error_rate > 0.0 && rng.r#gen::<f64>() < bit_error_rate {
                if !packet.bytes.is_empty() {
                    let bit_to_flip = rng.gen_range(0..packet.bytes.len());
                    packet.bytes[bit_to_flip] ^= 1 << rng.gen_range(0..8);
                    stats.corrupted_packets += 1;
                    println!("Corrupted packet during delivery");
                }
            }
            true
        },
    )
}

impl Link {
    pub fn new(
        bit_error_rate: f64,
        delay_ms: u32,
        max_bandwidth: f64,
        ip: IpAddr,
        space_side: (u16, String),
        ground_side: (u16, String),
    ) -> Link {
        if bit_error_rate < 0.0 {
            println!("Bit error rate must be greater than zero.");
            exit(1);
        }

        if max_bandwidth < 0.0 {
            println!("Max bandwidth must be greater than zero.");
            exit(1);
        }
        let space_side = UdpConn::new(space_side.1, ip, space_side.0);
        let ground_side = UdpConn::new(ground_side.1, ip, ground_side.0);

        let mut loss_pipeline = LossPipeline::new();

        if bit_error_rate > 0.0 {
            loss_pipeline
                .functions
                .push(bit_error_function(bit_error_rate));
        }

        Link {
            bit_error_rate,
            delay_ms,
            max_bandwidth,
            space_side,
            ground_side,
            loss_pipeline,
        }
    }

    fn receive_from_space(
        &mut self,
        buffer: &mut [u8],
        stats: &mut LinkStatistics,
        pending: &mut Vec<Packet>,
    ) {
        match self.space_side.recv(buffer) {
            Ok((size, addr)) => {
                stats.received_packets += 1;
                stats.received_bytes += size as u64;

                let packet_data = buffer[..size].to_vec();
                let delivery_time = Instant::now() + Duration::from_millis(self.delay_ms as u64);
                let packet = Packet::new(packet_data, size as u32, addr, delivery_time, true);
                pending.push(packet);
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => eprintln!("Error receiving from space: {}", e),
        }
    }

    fn receive_from_ground(
        &mut self,
        buffer: &mut [u8],
        stats: &mut LinkStatistics,
        pending: &mut Vec<Packet>,
    ) {
        match self.ground_side.recv(buffer) {
            Ok((size, addr)) => {
                stats.received_packets += 1;
                stats.received_bytes += size as u64;

                let packet_data = buffer[..size].to_vec();
                let delivery_time = Instant::now() + Duration::from_millis(self.delay_ms as u64);
                let packet = Packet::new(packet_data, size as u32, addr, delivery_time, false);
                pending.push(packet);
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => eprintln!("Error receiving from ground: {}", e),
        }
    }

    fn deliver_pending_packets(
        &mut self,
        pending: &mut Vec<Packet>,
        stats: &mut LinkStatistics,
        rng: &mut dyn rand::RngCore,
    ) {
        let now = Instant::now();
        let loss_pipeline = &self.loss_pipeline;
        let ground_side = &self.ground_side;
        let space_side = &self.space_side;

        pending.retain_mut(|packet| {
            if now >= packet.send_time {
                if !loss_pipeline.process_packet(packet, rng, stats) {
                    return false;
                }

                let result = if packet.space_or_ground {
                    ground_side.send(&packet.bytes, packet.addr)
                } else {
                    space_side.send(&packet.bytes, packet.addr)
                };

                match result {
                    Ok(_) => {
                        stats.transmitted_packets += 1;
                        stats.transmitted_bytes += packet.bytes.len() as u64;
                    }
                    Err(e) => {
                        eprintln!("Failed to send packet: {}", e);
                    }
                }
                false // Remove from pending
            } else {
                true // Keep in pending
            }
        });
    }

    pub fn run(&mut self) -> io::Result<()> {
        let mut stats = LinkStatistics {
            received_packets: 0,
            received_bytes: 0,
            transmitted_packets: 0,
            transmitted_bytes: 0,
            corrupted_packets: 0,
        };

        let mut buffer = vec![0u8; 65535];
        let mut pending_packets: Vec<Packet> = Vec::new();
        let mut rng = rand::thread_rng();
        let mut last_stats = Instant::now();
        let loop_duration = Duration::from_micros(1000); // 1ms loop time
        println!("Delay: {} ms", self.delay_ms);
        println!("Bit Error Rate: {}", self.bit_error_rate);
        println!("Max Bandwidth: {} bytes/s", self.max_bandwidth);

        loop {
            let loop_start = Instant::now();

            // Receive from both sides
            self.receive_from_space(&mut buffer, &mut stats, &mut pending_packets);
            self.receive_from_ground(&mut buffer, &mut stats, &mut pending_packets);

            // Deliver packets whose time has come
            self.deliver_pending_packets(&mut pending_packets, &mut stats, &mut rng);

            // Print stats every 10 seconds
            if last_stats.elapsed() >= Duration::from_secs(10) {
                println!("Statistics");
                println!(
                    "Received: {} packets, {} bytes",
                    stats.received_packets, stats.received_bytes
                );
                println!(
                    "Transmitted: {} packets, {} bytes",
                    stats.transmitted_packets, stats.transmitted_bytes
                );
                println!("Corrupted: {} packets", stats.corrupted_packets);
                println!("Pending: {} packets\n", pending_packets.len());
                last_stats = Instant::now();
            }

            let elapsed = loop_start.elapsed();
            if elapsed < loop_duration {
                spin_sleep::sleep(loop_duration - elapsed);
            }
        }
    }
}

pub struct LinkStatistics {
    pub received_packets: u64,
    pub received_bytes: u64,
    pub transmitted_packets: u64,
    pub transmitted_bytes: u64,
    pub corrupted_packets: u64,
}

pub struct UdpConn {
    name: String,
    socket: UdpSocket,
    remote_addr: Option<SocketAddr>,
}

impl UdpConn {
    pub fn new(name: String, ip: IpAddr, port: u16) -> UdpConn {
        let socket_addr = SocketAddr::new(ip, port);
        let socket = match UdpSocket::bind(socket_addr) {
            Ok(socket) => socket,
            Err(e) => {
                eprintln!("Failed to bind socket to address {}", e);
                exit(1);
            }
        };

        // Set socket to non-blocking mode
        socket
            .set_nonblocking(true)
            .expect("Failed to set non-blocking mode");

        UdpConn {
            name,
            socket,
            remote_addr: None,
        }
    }

    pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (size, addr) = self.socket.recv_from(buf)?;

        // Store the remote address for future sends
        if self.remote_addr.is_none() {
            self.remote_addr = Some(addr);
            println!("[{}] Connected to remote {}", self.name, addr);
        }

        Ok((size, addr))
    }

    pub fn send(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.socket.send_to(buf, addr)
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}
