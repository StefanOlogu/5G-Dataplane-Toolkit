use std::fs;
use dataplane::handlers::{handle_ethernet_header, handle_global_header, handle_ip_header, handle_packet_header, handle_transport};


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
    let global_header = match handle_global_header(&bytes) {
        Ok(header) => header,
        Err(_) => return,
    };

    let mut packet_count = 1;
    let mut current_index = 24;

    println!("\nStarting to parse packets:\n");

    //Loop for packet parsing
    while current_index + 16 <= bytes.len() {
        let header_slice = &bytes[current_index..current_index + 16];
        //Extract packet header information
        let packet_header = match handle_packet_header(header_slice,global_header.big_endian(),global_header.is_nano(),packet_count){
            Ok(header) => header,
            Err(_) => break ,
        };

        let payload_length = packet_header.incl_len() as usize;
        let next_index = current_index + payload_length + 16;

        //Check for corrupted packets
        if next_index > bytes.len() {
            eprintln!("WARNING: Packet {} is truncated. End of file reached prematurely.", packet_count);
            break;
        }

        let payload_data = &bytes[current_index + 16 ..next_index];

        //Extracting ethernet header information
        let ethernet_header = match handle_ethernet_header(payload_data) {
            Ok(header) => header,
            Err(_) => {
                current_index += 16 + payload_length;
                packet_count += 1;
                continue;
            }
        };

        if payload_length >14 {
            let ip_payload = &payload_data[14..];
            match handle_ip_header(ip_payload,ethernet_header.ether_type()){
                Ok(Some((transport_payload,protocol))) => {
                    handle_transport(transport_payload,protocol);
                }
                Ok(None) => {

                }
                Err(e) => {
                    eprintln!("Failed to parse IP header for packet {} : {}", packet_count, e);
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

