use std::fs;
use dataplane::pcap::parse_global_header;

fn main(){
    let file = "pcap_file.pcap";

    let bytes = match fs::read(file) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error reading file: {}", e);
            return;
        }
    };

    match parse_global_header(&bytes) {
        Ok(global_header) => {
            println!("--- PCAP Global Header ---");
            println!("Magic Number:  0x{:08X}", global_header.magic_number());
            println!("Version:       {}.{}", global_header.version_major(), global_header.version_minor());
            println!("Timezone:      {}", global_header.thiszone());
            println!("SigFigs:       {}", global_header.sigfigs());
            println!("SnapLen:       {} bytes", global_header.snaplen());
            println!("LinkType:      {} (Network type)", global_header.linktype());
        }
        Err(e) => {
            eprintln!("Failed to parse PCAP global header: {}", e);
        }
    }
}