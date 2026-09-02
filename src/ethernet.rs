use std::convert::TryInto;
use std::error::Error;

#[derive(Debug)]
pub struct EthernetHeader{
    dest_mac: [u8; 6],
    src_mac: [u8; 6],
    ether_type: u16,
}

pub fn parse_ethernet_header(bytes: &[u8]) -> Result<EthernetHeader, Box<dyn Error>> {
    if bytes.len() < 14 {
        return Err("PacketHeader is too small for an Ethernet header".into());
    }

    let mut dest_mac = [0u8; 6];
    dest_mac.copy_from_slice(&bytes[0..6]);

    let mut src_mac = [0u8; 6];
    src_mac.copy_from_slice(&bytes[6..12]);

    let ether_type = u16::from_be_bytes(bytes[12..14].try_into().map_err(|_| "Failed to parse Ethernet type")?);

    Ok(EthernetHeader{
        dest_mac,
        src_mac,
        ether_type,
    })
}

pub fn format_mac(mac : &[u8]) -> String {
    format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

impl EthernetHeader {
    pub fn src_mac(&self) -> &[u8; 6] {
        &self.src_mac
    }
    pub fn ether_type(&self) -> u16 {
        self.ether_type
    }
    pub fn dest_mac(&self) -> &[u8; 6] {
        &self.dest_mac
    }
}