use std::error::Error;

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