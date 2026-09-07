use std::error::Error;

//TODO: SWAP THE LOGIC FOR THE ENDIANESS IN ORDER TO BE HELD IN THE STRUCT RATHER THAN CALCULATED EVERY TIME
//TODO: REFACTOR IPV4 IN ORDER TO ACCEPT IP OPTIONS

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

    let four: [u8; 4] = bytes[0..4].try_into()?;
    let magic = u32::from_be_bytes(four);
    let (is_valid, big_endian) = match magic {
        0xa1b2c3d4 => (true, true),
        0xd4c3b2a1 => (true, false),
        0xa1b23c4d => (true, true),
        0x4d3cb2a1 => (true, false),
        _ => (false, false),
    };

    let version_major = read_u16(&bytes[4..6],big_endian)?;
    let version_minor = read_u16(&bytes[6..8],big_endian)?;
    let thiszone = read_i32(&bytes[8..12],big_endian)?;
    let sigfigs = read_u32(&bytes[12..16],big_endian)?;
    let snaplen = read_u32(&bytes[16..20],big_endian)?;
    let linktype = read_u32(&bytes[20..24],big_endian)?;

    if is_valid{
        Ok(PcapGlobalHeader {
            magic_number: magic,
            big_endian,
            version_major,
            version_minor,
            thiszone,
            sigfigs,
            snaplen,
            linktype,
        })
    }
    else{
        Err("Failed to parse PCAP global header. Unknown magic_number".into())
    }

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
