use std::error::Error;

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
    big_endian: bool,
    is_nano: bool,
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

    let magic = u32::from_be_bytes(bytes[0..4].try_into()?); // read with BE for finding out endianess
    let (is_valid, big_endian,is_nano) = match magic {
        0xa1b2c3d4 => (true, true,false),
        0xd4c3b2a1 => (true, false,false),
        0xa1b23c4d => (true, true,true),
        0x4d3cb2a1 => (true, false,true),
        _ => (false, false,false),
    };

    if !is_valid {
        return Err("Invalid PCAP global header".into());
    }

    let magic = read_u32(&bytes[0..4], big_endian)?; // Read with the correct byte order

    let version_major = read_u16(&bytes[4..6],big_endian)?;
    let version_minor = read_u16(&bytes[6..8],big_endian)?;
    let thiszone = read_i32(&bytes[8..12],big_endian)?;
    let sigfigs = read_u32(&bytes[12..16],big_endian)?;
    let snaplen = read_u32(&bytes[16..20],big_endian)?;
    let linktype = read_u32(&bytes[20..24],big_endian)?;

        Ok(PcapGlobalHeader {
            magic_number: magic,
            big_endian,
            is_nano,
            version_major,
            version_minor,
            thiszone,
            sigfigs,
            snaplen,
            linktype,
        })
}

pub fn parse_packet_header(bytes: &[u8], big_endian:bool) -> Result<PcapPacketHeader, Box<dyn Error>> {
    if bytes.len() < 16 {
        return Err("PacketHeader is too small".into());
    }

    let ts_sec = read_u32(&bytes[0..4],big_endian)?;
    let ts_fractional = read_u32(&bytes[4..8],big_endian)?;
    let incl_len = read_u32(&bytes[8..12],big_endian)?;
    let orig_len = read_u32(&bytes[12..16],big_endian)?;


    Ok(PcapPacketHeader {
        ts_sec,
        ts_fractional,
        incl_len,
        orig_len,
    })
}

pub fn read_u32(bytes:&[u8], big_endian:bool) -> Result<u32, Box<dyn Error>> {
    let data = bytes.try_into().map_err(|_| "Failed to parse PCAP payload")?;
    Ok(if big_endian {
        u32::from_be_bytes(data)
    }
    else {
        u32::from_le_bytes(data)
    })
}

pub fn read_u16(bytes:&[u8], big_endian:bool) -> Result<u16, Box<dyn Error>> {
    let data = bytes.try_into().map_err(|_| "Failed to parse PCAP payload")?;
    Ok(if big_endian {
        u16::from_be_bytes(data)
    }
    else {
        u16::from_le_bytes(data)
    })
}

pub fn read_i32(bytes:&[u8], big_endian:bool) -> Result<i32, Box<dyn Error>> {
    let data = bytes.try_into().map_err(|_| "Failed to parse PCAP payload")?;
    Ok(if big_endian {
        i32::from_be_bytes(data)
    }
    else {
        i32::from_le_bytes(data)
    })
}

impl PcapGlobalHeader {
    pub fn magic_number(&self) -> u32 {
        self.magic_number
    }
    pub fn big_endian(&self) -> bool { self.big_endian }
    pub fn is_nano(&self) -> bool { self.is_nano }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_little_endian_global_header() {
        // Container fields stored LITTLE-endian (least significant byte first).
        let bytes = [
            0xD4, 0xC3, 0xB2, 0xA1, // magic (LE on disk) -> 0xA1B2C3D4
            0x02, 0x00,             // version_major = 2
            0x04, 0x00,             // version_minor = 4
            0x00, 0x00, 0x00, 0x00, // thiszone = 0
            0x00, 0x00, 0x00, 0x00, // sigfigs = 0
            0xFF, 0xFF, 0x00, 0x00, // snaplen = 65535
            0x01, 0x00, 0x00, 0x00, // linktype = 1
        ];

        let hdr = parse_global_header(&bytes).unwrap();

        assert_eq!(hdr.big_endian(), false);
        assert_eq!(hdr.magic_number(), 0xA1B2C3D4);
        assert_eq!(hdr.version_major(), 2);
        assert_eq!(hdr.version_minor(), 4);
        assert_eq!(hdr.snaplen(), 65535);
        assert_eq!(hdr.linktype(), 1);
        assert!(parse_global_header(&[0u8; 24]).is_err())
    }

    #[test]
    fn parses_big_endian_global_header() {
        // SAME logical values, stored BIG-endian (most significant byte first).
        let bytes = [
            0xA1, 0xB2, 0xC3, 0xD4, // magic (BE on disk) -> 0xA1B2C3D4
            0x00, 0x02,             // version_major = 2
            0x00, 0x04,             // version_minor = 4
            0x00, 0x00, 0x00, 0x00, // thiszone = 0
            0x00, 0x00, 0x00, 0x00, // sigfigs = 0
            0x00, 0x00, 0xFF, 0xFF, // snaplen = 65535
            0x00, 0x00, 0x00, 0x01, // linktype = 1
        ];

        let hdr = parse_global_header(&bytes).unwrap();

        assert_eq!(hdr.big_endian(), true);
        assert_eq!(hdr.magic_number(), 0xA1B2C3D4);
        assert_eq!(hdr.version_major(), 2);
        assert_eq!(hdr.version_minor(), 4);
        assert_eq!(hdr.snaplen(), 65535);
        assert_eq!(hdr.linktype(), 1);
        assert!(parse_global_header(&[0u8; 24]).is_err())
    }
}
