use std::error::Error;

#[derive(Debug)]
pub struct UdpHeader {
    src_port: u16,
    dest_port: u16,
    length: u16,
    checksum: u16,
}

#[derive(Debug)]
pub struct TcpHeader {
    src_port: u16,
    dest_port: u16,
    sequence_number: u32,
    ack_number: u32,
    data_offset: u8,
    header_length: u8,
    reserved: u8,
    flags: u8,
    window_size: u16,
    checksum: u16,
    urgent_pointer: u16,
}


pub fn parse_udp_header(bytes: &[u8]) -> Result<UdpHeader, Box<dyn Error>> {
    if bytes.len() < 8 {
        return Err("Payload too small for a UDP header".into());
    }

    let src_port= u16::from_be_bytes(bytes[0..2].try_into().map_err(|_| "Failed to parse source port")?);
    let dest_port = u16::from_be_bytes(bytes[2..4].try_into().map_err(|_| "Failed to parse destination port")?);
    let length= u16::from_be_bytes(bytes[4..6].try_into().map_err(|_| "Failed to parse length")?);
    let checksum= u16::from_be_bytes(bytes[6..8].try_into().map_err(|_| "Failed to parse checksum")?);

    Ok(UdpHeader {
        src_port,
        dest_port,
        length,
        checksum,
    })
}

pub fn parse_tcp_header(bytes: &[u8]) -> Result<TcpHeader, Box<dyn Error>> {
    if bytes.len() < 20 {
        return Err("Payload too small for a TCP header".into());
    }

    let src_port= u16::from_be_bytes(bytes[0..2].try_into().map_err(|_| "Failed to parse source port")?);
    let dest_port = u16::from_be_bytes(bytes[2..4].try_into().map_err(|_| "Failed to parse destination port")?);
    let sequence_number = u32::from_be_bytes(bytes[4..8].try_into().map_err(|_| "Failed to parse sequence number")?);
    let ack_number = u32::from_be_bytes(bytes[8..12].try_into().map_err(|_| "Failed to parse ACK number")?);

    let offset_reserved= bytes[12];
    let data_offset = offset_reserved >>4;

    if data_offset < 5 {
        return Err("TCP data offset too small".into());
    }

    let header_length = data_offset * 4;

    if bytes.len() < header_length as usize {
        return Err("TCP header length exceeds available bytes".into());
    }

    let reserved = offset_reserved & 0x0f;

    let flags = bytes[13];
    let window_size = u16::from_be_bytes(bytes[14..16].try_into().map_err(|_| "Failed to parse window size")?);
    let checksum = u16::from_be_bytes(bytes[16..18].try_into().map_err(|_| "Failed to parse checksum")?);
    let urgent_pointer = u16::from_be_bytes(bytes[18..20].try_into().map_err(|_| "Failed to parse urgent pointer")?);

    Ok(TcpHeader{
        src_port,
        dest_port,
        sequence_number,
        ack_number,
        data_offset,
        header_length,
        reserved,
        flags,
        window_size,
        checksum,
        urgent_pointer,
    })
}

impl UdpHeader {
    pub fn src_port(&self) -> u16 {
        self.src_port
    }
    pub fn dest_port(&self) -> u16 {
        self.dest_port
    }
    pub fn length(&self) -> u16 {
        self.length
    }
    pub fn checksum(&self) -> u16 {
        self.checksum
    }
}

impl TcpHeader {
    pub fn src_port(&self) -> u16 {
        self.src_port
    }
    pub fn dest_port(&self) -> u16 {
        self.dest_port
    }
    pub fn sequence_number(&self) -> u32 {
        self.sequence_number
    }
    pub fn ack_number(&self) -> u32 {
        self.ack_number
    }
    pub fn data_offset(&self) -> u8 {
        self.data_offset
    }
    pub fn header_length(&self) -> u8 {
        self.header_length
    }
    pub fn reserved(&self) -> u8 {
        self.reserved
    }
    pub fn flags(&self) -> u8 {
        self.flags
    }
    pub fn window_size(&self) -> u16 {
        self.window_size
    }
    pub fn checksum(&self) -> u16 {
        self.checksum
    }
    pub fn urgent_pointer(&self) -> u16 {
        self.urgent_pointer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---UDP---
    #[test]
    fn parses_udp_header() {
        let bytes = [
            0xB3, 0x6B, // src_port = 45931
            0x01, 0xBB, // dst_port = 443
            0x00, 0x29, // length   = 41
            0xE6, 0x2C, // checksum = 58924
        ];

        let udp = parse_udp_header(&bytes).unwrap();

        assert_eq!(udp.src_port(), 45931);
        assert_eq!(udp.dest_port(), 443);
        assert_eq!(udp.length(), 41);
        assert_eq!(udp.checksum(), 58924);
    }

    #[test]
    fn rejects_short_udp_header() {
        let bytes = [0x00, 0x01, 0x02]; // only 3 bytes, need 8
        assert!(parse_udp_header(&bytes).is_err());
    }

    // ---TCP---
    #[test]
    fn parses_tcp_header() {
        let bytes = [
            0xB3, 0x6B,             // src_port = 45931
            0x01, 0xBB,             // dest_port = 443
            0x12, 0x34, 0x56, 0x78, // sequence_number = 0x12345678 = 305419896
            0x00, 0x00, 0x00, 0x01, // ack_number = 1
            0x50,                   // data_offset = 5 , reserved = 0
            0x02,                   // flags = 0x02 (SYN)
            0xFF, 0xFF,             // window_size = 65535
            0x1A, 0x2B,             // checksum = 0x1A2B = 6699
            0x00, 0x00,             // urgent_pointer = 0
        ];

        let tcp = parse_tcp_header(&bytes).unwrap();

        assert_eq!(tcp.src_port(), 45931);
        assert_eq!(tcp.dest_port(), 443);
        assert_eq!(tcp.sequence_number(), 0x12345678);
        assert_eq!(tcp.ack_number(), 1);
        assert_eq!(tcp.data_offset(), 5);
        assert_eq!(tcp.header_length(), 20);
        assert_eq!(tcp.reserved(), 0);
        assert_eq!(tcp.flags(), 0x02);
        assert_eq!(tcp.window_size(), 65535);
        assert_eq!(tcp.checksum(), 0x1A2B);
        assert_eq!(tcp.urgent_pointer(), 0);
    }

    #[test]
    fn rejects_short_tcp_header() {
        let bytes = [0x00, 0x01, 0x02];
        assert!(parse_tcp_header(&bytes).is_err());
    }

    #[test]
    fn rejects_tcp_bad_data_offset(){
        let bytes = [
            0xB3, 0x6B,             // src_port = 45931
            0x01, 0xBB,             // dest_port = 443
            0x12, 0x34, 0x56, 0x78, // sequence_number = 0x12345678 = 305419896
            0x00, 0x00, 0x00, 0x01, // ack_number = 1
            0x40,                   // data_offset = 4, should activate guard for data offset too small
            0x02,                   // flags = 0x02 (SYN)
            0xFF, 0xFF,             // window_size = 65535
            0x1A, 0x2B,             // checksum = 0x1A2B = 6699
            0x00, 0x00,             // urgent_pointer = 0
        ];

        assert!(parse_tcp_header(&bytes).is_err());
    }
}