use std::fs;
use dataplane::pcap::{parse_global_header, parse_packet_header};

fn main(){
    let file = "pcap_file.pcap";

    let bytes = match fs::read(file) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error reading file: {}", e);
            return;
        }
    };

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

    let is_nano = global_header.magic_number() == 0xa1b23c4d;
    let mut packet_count = 1;

    let mut current_index = 24;

    println!("\nStarting to parse packets:");

    while current_index + 16 < bytes.len() {
        let header_slice = &bytes[current_index..current_index + 16];

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

        if current_index + payload_length + 16 > bytes.len() {
            eprintln!("WARNING: Packet {} is truncated. End of file reached prematurely.", packet_count);
        }

        let payload_data = &bytes[current_index + 16 ..current_index + 16 + payload_length];
        //TO DO: Analyze extracted payload data


        current_index += 16 + payload_length;
        packet_count += 1;
    }

    println!("\nFinished parsing! Total packets read: {}", packet_count - 1);
}