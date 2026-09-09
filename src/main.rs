use std::fs;
use dataplane::ethernet;
use dataplane::ip;
use dataplane::pcap;
use dataplane::transport;


fn main(){
    let file = "pcap_file.pcap";

    //Read the file into a vector
    let bytes = match fs::read(file) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error reading file: {}", e);
            return;
        }
    };

    //Extracting global header information
    let global_header = match pcap::parse_global_header(&bytes) {
        Ok(global_header) => {
            println!("--- PCAP Global Header ---");
            println!("Magic Number:  0x{:08X}", global_header.magic_number());
            println!("Version:       {}.{}", global_header.version_major(), global_header.version_minor());
            println!("Timezone:      {}", global_header.thiszone());
            println!("SigFigs:       {}", global_header.sigfigs());
            println!("SnapLen:       {} bytes", global_header.snaplen());
            println!("LinkType:      {} (Network type)", global_header.linktype());
            global_header
        }
        Err(e) => {
            eprintln!("Failed to parse PCAP global header: {}", e);
            return;
        }
    };

    let mut packet_count = 1;

    let mut current_index = 24;

    println!("\nStarting to parse packets:\n");

    //Loop for packet parsing
    while current_index + 16 <= bytes.len() {
        let header_slice = &bytes[current_index..current_index + 16];
        let unit = if global_header.is_nano() { "nanoseconds" } else { "microseconds" };


        //Extract packet header information
        let packet_header = match pcap::parse_packet_header(header_slice,global_header.big_endian()) {
            Ok(packet_header) => {
                println!("---PACKET NUMBER {}---  \n\n  Timestamp: {} seconds, {} {}  |  Included size: {}  |  Original size: {}", packet_count,packet_header.ts_sec(), packet_header.ts_fractional(), unit,packet_header.incl_len(),packet_header.orig_len());
                println!();
                packet_header
            }
            Err(e) => {
                eprintln!("Failed to parse header for packet {}:{}", packet_count, e);
                break;
            }
        };

        let payload_length = packet_header.incl_len() as usize;

        let next_index = current_index + payload_length + 16;

        //Check for corrupted packets
        if next_index > bytes.len() {
            eprintln!("WARNING: Packet {} is truncated. End of file reached prematurely.", packet_count);
            break;
        }

        let payload_data = &bytes[current_index + 16 ..next_index];
        //TO DO: Analyze extracted payload data

        //Extracting ethernet header information
        let ethernet_header = match ethernet::parse_ethernet_header(payload_data) {
            Ok(ethernet_header) => {
                println!("  Destination MAC address: {}", ethernet::format_mac(ethernet_header.dest_mac()));
                println!("  Source MAC address : {}", ethernet::format_mac(ethernet_header.src_mac()));
                println!("  EtherType: 0x{:04X}", ethernet_header.ether_type());
                ethernet_header
            }
            Err(e) => {
                eprintln!("Failed to parse Ethernet header for packet number{}: {}",packet_count,e);
                //Skip to next packet to avoid infinite loop
                current_index += 16 + payload_length;
                packet_count += 1;
                println!();
                continue;
            }
        };

        if payload_length >14 {
            let ip_payload = &payload_data[14..];
            let transport_info = match ethernet_header.ether_type() {
                //IPv4
                0x0800 => {
                    match ip::parse_ipv4_header(ip_payload) {
                        Ok(ipv4) => {
                            println!("    Version:         {}", ipv4.version());
                            println!("    IHL:             {} ({} bytes)", ipv4.ihl(), ipv4.ihl() * 4);
                            println!("    TOS:             0x{:02X}", ipv4.tos());
                            println!("    Total Length:    {}", ipv4.total_length());
                            println!("    Identification:  0x{:04X}", ipv4.identification());
                            println!("    Flags:           0x{:X}", ipv4.flags());
                            println!("    Fragment Offset: {}", ipv4.fragment_offset());
                            println!("    TTL:             {}", ipv4.ttl());
                            println!("    Protocol:        {}", ipv4.protocol());
                            println!("    Checksum:        0x{:04X}", ipv4.header_checksum());
                            println!("    Source IP:       {}", ipv4.src_ip());
                            println!("    Destination IP:  {}", ipv4.dest_ip());

                            //allow options
                            let start = ipv4.header_length() as usize;
                            let end = (ipv4.total_length() as usize).min(ip_payload.len());
                            println!();
                            Some((&ip_payload[start..end], ipv4.protocol()))   // hand back slice + protocol

                        }
                        Err(e) => {
                            eprintln!("Failed to parse IPv4 header for packet {}: {}", packet_count, e);
                            None
                        }
                    }
                }
                0x86DD =>{
                    //IPv6
                    match ip::parse_ipv6_header(ip_payload) {
                        Ok(ipv6) => {
                            println!("    Version:         {}", ipv6.version());
                            println!("    Traffic Class:   0x{:02X}", ipv6.traffic_class());
                            println!("    Flow Label:      0x{:05X}", ipv6.flow_label());
                            println!("    Payload Length:  {}", ipv6.payload_length());
                            println!("    Next Header:     {}", ipv6.next_header());
                            println!("    Hop Limit:       {}", ipv6.hop_limit());
                            println!("    Source IP:       {}", ipv6.src_ip());
                            println!("    Destination IP:  {}", ipv6.dest_ip());
                            println!();

                            let start = 40;
                            let end = (40 + ipv6.payload_length() as usize).min(ip_payload.len());
                            Some((&ip_payload[start..end], ipv6.next_header()))
                        }
                        Err(e) => {
                            eprintln!("Failed to parse IPv6 header for packet {}: {}",packet_count, e);
                            None
                        }
                    }
                }
                //Unknown
                other => {
                    println!("    Unknown EtherType: 0x{:04X}, skipping IP parsing.", other);
                    None
                }
            };

            //TODO:Transport parsing
            if let Some((payload, protocol)) = transport_info {
                match protocol {
                    6 => {

                    }
                    17 => {
                        match transport::parse_udp_header(payload) {
                            Ok(udp_header) => {
                                println!("  UDP Header:");
                                println!("    Src Port: {}", udp_header.src_port());
                                println!("    Dst Port: {}", udp_header.dst_port());
                                println!("    Length: {}", udp_header.length());
                                println!("    Checksum: {}", udp_header.checksum());
                                println!();
                            }
                            Err(e) => {
                                eprintln!("Failed to parse UDP header for packet {}: {}", packet_count, e);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        else{
            println!();
        }

        //Move to the next packet
        current_index += 16 + payload_length;
        packet_count += 1;
    }

    println!("\nFinished parsing! Total packets read: {}", packet_count - 1);
}

