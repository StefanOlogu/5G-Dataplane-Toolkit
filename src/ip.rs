use std::convert::TryInto;
use std::error::Error;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug)]
pub struct Ipv4Header {
    version: u8,
    ihl: u8,
    header_length: u8,
    tos: u8,
    total_length: u16,
    identification: u16,
    flags: u8,
    fragment_offset: u16,
    ttl: u8,
    protocol: u8,
    header_checksum: u16,
    src_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
}

#[derive(Debug)]
pub struct Ipv6Header {
    version: u8,
    traffic_class: u8,
    flow_label: u32,
    payload_length: u16,
    next_header: u8,
    hop_limit: u8,
    src_ip: Ipv6Addr,
    dest_ip: Ipv6Addr,
}

pub fn parse_ipv4_header(bytes: &[u8]) -> Result<Ipv4Header, Box<dyn Error>> {
    if bytes.len() < 20 {
        return Err("Payload is too small for an IPv4 header".into());
    }

    let version_ihl= bytes[0];          //first 4 bits are the version, last 4 bits are the IHL
    let version = version_ihl >> 4;     //extract top 4 bits
    let ihl = version_ihl & 0x0f;       //extract bottom 4 bits
    if ihl <5{
        return Err("Ihl too small for an IPv4 header".into());
    }

    let header_length = ihl * 4;
    if bytes.len() < header_length as usize {
        return Err("IPv4 header length exceeds available bytes".into());
    }

    let tos = bytes[1];
    let total_length = u16::from_be_bytes(bytes[2..4].try_into().map_err(|_| "Failed to parse total length")?);
    let identification = u16::from_be_bytes(bytes[4..6].try_into().map_err(|_| "Failed to parse identification")?);

    let flags_frag = u16::from_be_bytes(bytes[6..8].try_into().map_err(|_| "Failed to parse flags fragment")?);
    let flags = (flags_frag >> 13) as u8;       //flag is the top 3 bits
    let fragment_offset = flags_frag & 0x1fff; //offset is the bottom 13 bits

    let ttl = bytes[8];
    let protocol = bytes[9];
    let header_checksum = u16::from_be_bytes(bytes[10..12].try_into().map_err(|_| "Failed to parse header checksum")?);


    let src_ip = Ipv4Addr::new(bytes[12],bytes[13],bytes[14],bytes[15]);
    let dest_ip = Ipv4Addr::new(bytes[16],bytes[17],bytes[18],bytes[19]);

    Ok(Ipv4Header{
        version,
        ihl,
        header_length,
        tos,
        total_length,
        identification,
        flags,
        fragment_offset,
        ttl,
        protocol,
        header_checksum,
        src_ip,
        dest_ip
    })
}

pub fn parse_ipv6_header(bytes: &[u8]) -> Result<Ipv6Header, Box<dyn Error>> {
    if bytes.len() < 40 {
        return Err("Payload is too small for an IPv6 header".into());
    }

    let v_tc_fl = u32::from_be_bytes(bytes[0..4].try_into()?); //first 4 bytes contain the version, traffic class and the flow

    let version = (v_tc_fl >> 28) as u8;                    // Top 4 bits
    let traffic_class = ((v_tc_fl >> 20) & 0xFF) as u8;     // Next 8 bits
    let flow_label = v_tc_fl & 0x000F_FFFF;                 // Bottom 20 bits

    let payload_length = u16::from_be_bytes(bytes[4..6].try_into().map_err(|_| "Failed to parse payload_length")?);
    let next_header = bytes[6];
    let hop_limit = bytes[7];

    let mut src_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&bytes[8..24]);
    let src_ip = Ipv6Addr::from(src_bytes);

    let mut dst_bytes = [0u8; 16];
    dst_bytes.copy_from_slice(&bytes[24..40]);
    let dest_ip = Ipv6Addr::from(dst_bytes);

    Ok(Ipv6Header {
        version, traffic_class, flow_label,
        payload_length, next_header, hop_limit, src_ip, dest_ip
    })
}

impl Ipv4Header {
    pub fn src_ip(&self) -> &Ipv4Addr {
        &self.src_ip
    }
    pub fn dest_ip(&self) -> &Ipv4Addr {
        &self.dest_ip
    }
    pub fn protocol(&self) -> u8 {
        self.protocol
    }
    pub fn version(&self) -> u8 {
        self.version
    }
    pub fn ihl(&self) -> u8 { self.ihl }
    pub fn header_length(&self) -> u8 {self.header_length}
    pub fn tos(&self) -> u8 {
        self.tos
    }
    pub fn total_length(&self) -> u16 {
        self.total_length
    }
    pub fn identification(&self) -> u16 {
        self.identification
    }
    pub fn flags(&self) -> u8 {
        self.flags
    }
    pub fn fragment_offset(&self) -> u16 {
        self.fragment_offset
    }
    pub fn ttl(&self) -> u8 {
        self.ttl
    }
    pub fn header_checksum(&self) -> u16 {
        self.header_checksum
    }
}

impl Ipv6Header {
    pub fn src_ip(&self) -> &Ipv6Addr {
        &self.src_ip
    }
    pub fn dest_ip(&self) -> &Ipv6Addr {
        &self.dest_ip
    }
    pub fn version(&self) -> u8 {
        self.version
    }
    pub fn traffic_class(&self) -> u8 {
        self.traffic_class
    }
    pub fn flow_label(&self) -> u32 {
        self.flow_label
    }
    pub fn payload_length(&self) -> u16 {
        self.payload_length
    }
    pub fn next_header(&self) -> u8 {
        self.next_header
    }
    pub fn hop_limit(&self) -> u8 {
        self.hop_limit
    }
}