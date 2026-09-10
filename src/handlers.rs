use crate::pcap::{PcapGlobalHeader, PcapPacketHeader};
use std::error::Error;
use crate::ethernet::EthernetHeader;
use crate::{ethernet, ip, pcap, transport};

type TransportInfo<'a> = Option<(&'a [u8], u8)>;

pub fn handle_global_header(bytes: &[u8]) -> Result<PcapGlobalHeader, Box<dyn Error>> {
    let global_header = pcap::parse_global_header(bytes)?;
    println!("--- PCAP Global Header ---");
    println!("Magic Number:  0x{:08X}", global_header.magic_number());
    println!("Version:       {}.{}", global_header.version_major(), global_header.version_minor());
    println!("Timezone:      {}", global_header.thiszone());
    println!("SigFigs:       {}", global_header.sigfigs());
    println!("SnapLen:       {} bytes", global_header.snaplen());
    println!("LinkType:      {} (Network type)", global_header.linktype());
    Ok(global_header)
}

pub fn handle_packet_header(bytes: &[u8], big_endian : bool, is_nano: bool, packet_count: usize) -> Result<PcapPacketHeader, Box<dyn Error>> {
    let unit = if is_nano { "nanoseconds" } else { "microseconds" };
    let packet_header = pcap::parse_packet_header(bytes,big_endian)?;
    println!("---PACKET NUMBER {}---  \n\n  Timestamp: {} seconds, {} {}  |  Included size: {}  |  Original size: {}", packet_count,packet_header.ts_sec(), packet_header.ts_fractional(), unit,packet_header.incl_len(),packet_header.orig_len());
    println!();
    Ok(packet_header)
}

pub fn handle_ethernet_header(bytes: &[u8]) -> Result<EthernetHeader, Box<dyn Error>> {
    let ethernet_header = ethernet::parse_ethernet_header(bytes)?;
    println!("  Destination MAC address: {}", ethernet::format_mac(ethernet_header.dest_mac()));
    println!("  Source MAC address : {}", ethernet::format_mac(ethernet_header.src_mac()));
    println!("  EtherType: 0x{:04X}", ethernet_header.ether_type());
    Ok(ethernet_header)
}

pub fn handle_ip_header<'a>(ip_payload : &'a [u8], ether_type: u16) -> Result<TransportInfo<'a>, Box<dyn Error>> {
    match ether_type {
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
                    Ok(Some((&ip_payload[start..end], ipv4.protocol())))   // hand back slice + protocol

                }
                Err(e) => {
                    Err(e)
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
                    Ok(Some((&ip_payload[start..end], ipv6.next_header())))
                }
                Err(e) => {
                    Err(e)
                }
            }
        }
        //Unknown
        other => {
            println!("Unknown EtherType: 0x{:04X}, skipping IP parsing.", other);
            Ok(None)
        }
    }
}

pub fn handle_transport(payload : &[u8], protocol: u8){
    match protocol {
        6 => {
            match transport::parse_tcp_header(payload) {
                Ok(tcp_header) => {
                    println!("  TCP Header:");
                    println!("    Src Port: {}", tcp_header.src_port());
                    println!("    Dest Port: {}", tcp_header.dest_port());
                    println!("    Sequence Number: {}", tcp_header.sequence_number());
                    println!("    Acknowledgment Number: {}",tcp_header.ack_number());
                    println!("    Data Offset: {}", tcp_header.data_offset());
                    println!("    Reserved: {}", tcp_header.reserved());
                    println!("    Flags: {}",tcp_header.flags());
                    println!("    Window Size: {}",tcp_header.window_size());
                    println!("    Checksum: {}", tcp_header.checksum());
                    println!("    Urgent Pointer: {}",tcp_header.urgent_pointer());
                    println!();
                }
                Err(e) => {
                    eprintln!("Failed to parse TCP header: {}", e);
                }
            }
        }
        17 => {
            match transport::parse_udp_header(payload) {
                Ok(udp_header) => {
                    println!("  UDP Header:");
                    println!("    Src Port: {}", udp_header.src_port());
                    println!("    Dest Port: {}", udp_header.dest_port());
                    println!("    Length: {}", udp_header.length());
                    println!("    Checksum: {}", udp_header.checksum());
                    println!();
                }
                Err(e) => {
                    eprintln!("Failed to parse UDP header: {}", e);
                }
            }
        }
        _ => {}
    }
}
