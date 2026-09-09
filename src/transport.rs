use std::error::Error;

#[derive(Debug)]
pub struct UdpHeader {
    src_port: u16,
    dest_port: u16,
    length: u16,
    checksum: u16,
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

impl UdpHeader {
    pub fn src_port(&self) -> u16 {
        self.src_port
    }
    pub fn dst_port(&self) -> u16 {
        self.dest_port
    }
    pub fn length(&self) -> u16 {
        self.length
    }
    pub fn checksum(&self) -> u16 {
        self.checksum
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(udp.dst_port(), 443);
        assert_eq!(udp.length(), 41);
        assert_eq!(udp.checksum(), 58924);
    }

    #[test]
    fn rejects_short_udp_header() {
        let bytes = [0x00, 0x01, 0x02]; // only 3 bytes, need 8
        assert!(parse_udp_header(&bytes).is_err());
    }
}