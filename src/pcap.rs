use std::error::Error;

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

pub fn parse_packet_header(bytes: &[u8], is_nano: bool, packet_number : usize) -> Result<PcapPacketHeader, Box<dyn Error>> {
    if bytes.len() < 16 {
        return Err("PacketHeader is too small".into());
    }

    let ts_sec = u32::from_le_bytes(bytes[0..4].try_into().map_err(|_| "Failed to parse seconds")?);
    let ts_fractional = u32::from_le_bytes(bytes[4..8].try_into().map_err(|_| "Failed to parse fractional timestamp")?);
    let incl_len = u32::from_le_bytes(bytes[8..12].try_into().map_err(|_| "Failed to parse included length")?);

    let unit = if is_nano { "nanoseconds" } else { "microseconds" };

    println!("Packet number {}   Timestamp: {} seconds, {} {}       Included size: {}", packet_number,ts_sec, ts_fractional, unit,incl_len);

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