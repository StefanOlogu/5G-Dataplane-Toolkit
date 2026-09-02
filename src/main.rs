use std::fs;
use dataplane::pcap::{format_mac, parse_ethernet_header, parse_global_header, parse_packet_header};

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
    let global_header = match parse_global_header(&bytes) {
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

    //is_nano is used to check for Little-Endian
    let is_nano = global_header.magic_number() == 0xa1b23c4d;
    let mut packet_count = 1;

    let mut current_index = 24;

    println!("\nStarting to parse packets:\n");

    //Loop for packet parsing
    while current_index + 16 < bytes.len() {
        let header_slice = &bytes[current_index..current_index + 16];

        //Extract packet header information
        let packet_header = match parse_packet_header(header_slice, is_nano, packet_count) {
            Ok(packet_header) => {
                packet_header
            }
            Err(e) => {
                eprintln!("Failed to parse header for packet {}:{}", packet_count, e);
                break;
            }
        };

        let payload_length = packet_header.incl_len() as usize;

        //Check for corrupted packets
        if current_index + payload_length + 16 > bytes.len() {
            eprintln!("WARNING: Packet {} is truncated. End of file reached prematurely.", packet_count);
        }

        let payload_data = &bytes[current_index + 16 ..current_index + 16 + payload_length];
        //TO DO: Analyze extracted payload data

        //Extracting ethernet header information
        let ethernet_header = match parse_ethernet_header(payload_data) {
            Ok(ethernet_header) => {
                println!(" Destination MAC address: {}", format_mac(ethernet_header.dest_mac()));
                println!(" Source MAC address : {}", format_mac(ethernet_header.src_mac()));
                println!(" EtherType: 0x{:4X}", ethernet_header.ether_type());
                println!();
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

        //Move to the next packet
        current_index += 16 + payload_length;
        packet_count += 1;
    }

    println!("\nFinished parsing! Total packets read: {}", packet_count - 1);
}

