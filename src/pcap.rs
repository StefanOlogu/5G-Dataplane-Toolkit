use std::error::Error;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug)]
pub struct Ipv4Header {
    version: u8,
    ihl: u8,
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

//HEADER TYPES
#[derive(Debug)]
pub struct EthernetHeader{
    dest_mac: [u8; 6],
    src_mac: [u8; 6],
    ether_type: u16,
}

#[derive(Debug)]
pub struct PcapPacketHeader{
    ts_sec : u32,
    ts_fractional : u32,
    incl_len: u32,
    orig_len: u32,
}

#[derive(Debug)]
pub struct PcapGlobalHeader{
    magic_number: u32,
    version_major: u16,
    version_minor: u16,
    thiszone: i32,
    sigfigs: u32,
    snaplen: u32,
    linktype: u32,
}

//PARSING FUNCTIONS FOR EACH TYPE OF HEADER
pub fn parse_global_header(bytes: &[u8]) -> Result<PcapGlobalHeader, Box<dyn Error>> {
    if bytes.len() < 24 {
        return Err("File is too small to contain a PCAP global header".into());
    }

    let magic = u32::from_le_bytes(
        bytes[0..4].try_into().map_err(|_| "Failed to parse magic number")?
    );

    if magic != 0xa1b2c3d4 && magic != 0xa1b23c4d {
        return Err(format!("Unsupported magic number: 0x{:08X}", magic).into());
    }

    Ok(PcapGlobalHeader {
        magic_number: magic,
        version_major: u16::from_le_bytes(bytes[4..6].try_into().map_err(|_| "Failed to parse major version")?),
        version_minor: u16::from_le_bytes(bytes[6..8].try_into().map_err(|_| "Failed to parse minor version")?),
        thiszone: i32::from_le_bytes(bytes[8..12].try_into().map_err(|_| "Failed to parse timezone")?),
        sigfigs: u32::from_le_bytes(bytes[12..16].try_into().map_err(|_| "Failed to parse sigfigs")?),
        snaplen: u32::from_le_bytes(bytes[16..20].try_into().map_err(|_| "Failed to parse snaplen")?),
        linktype: u32::from_le_bytes(bytes[20..24].try_into().map_err(|_| "Failed to parse linktype")?),
    })
}

pub fn parse_packet_header(bytes: &[u8]) -> Result<PcapPacketHeader, Box<dyn Error>> {
    if bytes.len() < 16 {
        return Err("PacketHeader is too small".into());
    }

    let ts_sec = u32::from_le_bytes(bytes[0..4].try_into().map_err(|_| "Failed to parse seconds")?);
    let ts_fractional = u32::from_le_bytes(bytes[4..8].try_into().map_err(|_| "Failed to parse fractional timestamp")?);
    let incl_len = u32::from_le_bytes(bytes[8..12].try_into().map_err(|_| "Failed to parse included length")?);


    Ok(PcapPacketHeader {
        ts_sec,
        ts_fractional,
        incl_len,
        orig_len : u32::from_le_bytes(bytes[12..16].try_into().map_err(|_| " Failed to parse original length")?),
    })
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

pub fn parse_ipv4_header(bytes: &[u8]) -> Result<Ipv4Header, Box<dyn Error>> {
    if bytes.len() < 20 {
        return Err("Payload is too small for an IPv4 header".into());
    }

    let version_ihl= bytes[0];          //first 4 bits are the version, last 4 bits are the IHL
    let version = version_ihl >> 4;     //extract top 4 bits
    let ihl = version_ihl & 0x0f;       //extract bottom 4 bits

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

pub fn format_mac(mac : &[u8]) -> String {
    format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

//GETTERS FOR EACH TYPE OF HEADER
impl PcapGlobalHeader {
    pub fn magic_number(&self) -> u32 {
        self.magic_number
    }
    pub fn version_major(&self) -> u16 {
        self.version_major
    }
    pub fn version_minor(&self) -> u16 {
        self.version_minor
    }
    pub fn thiszone(&self) -> i32 {
        self.thiszone
    }
    pub fn sigfigs(&self) -> u32 {
        self.sigfigs
    }
    pub fn snaplen(&self) -> u32 {
        self.snaplen
    }
    pub fn linktype(&self) -> u32 {
        self.linktype
    }
}

impl PcapPacketHeader {
    pub fn ts_sec(&self) -> u32 {
        self.ts_sec
    }
    pub fn ts_fractional(&self) -> u32 {
        self.ts_fractional
    }
    pub fn incl_len(&self) -> u32 {
        self.incl_len
    }
    pub fn orig_len(&self) -> u32 {
        self.orig_len
    }
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
    pub fn ihl(&self) -> u8 {
        self.ihl
    }
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