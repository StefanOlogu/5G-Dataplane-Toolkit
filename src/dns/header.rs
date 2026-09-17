use std::error::Error;

#[derive(Debug)]
pub struct DnsHeader {
    id: u16,
    qr: bool,
    opcode: u8,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    z: u8,
    rcode: u8,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

pub fn parse_dns_header(bytes: &[u8]) -> Result<DnsHeader, Box<dyn Error>> {
    if bytes.len() < 12 {
        return Err("dns header too short".into());
    }

    let id = u16::from_be_bytes(bytes[0..2].try_into()?);
    let qr = bytes[2] & 0x80 != 0;
    let opcode = (bytes[2] & 0x78) >> 3;
    let aa = bytes[2] & 0x04 != 0;
    let tc = bytes[2] & 0x02 != 0;
    let rd = bytes[2] & 0x01 != 0;
    let ra = bytes[3] & 0x80 != 0;
    let z = (bytes[3] & 0x70) >> 4;
    let rcode = bytes[3] & 0x0F;

    let qdcount = u16::from_be_bytes(bytes[4..6].try_into()?);
    let ancount = u16::from_be_bytes(bytes[6..8].try_into()?);
    let nscount = u16::from_be_bytes(bytes[8..10].try_into()?);
    let arcount = u16::from_be_bytes(bytes[10..12].try_into()?);

    Ok(DnsHeader {
        id,
        qr,
        opcode,
        aa,
        tc,
        rd,
        ra,
        z,
        rcode,
        qdcount,
        ancount,
        nscount,
        arcount,
    })
}

impl DnsHeader {
    pub fn id(&self) -> u16 {
        self.id
    }
    pub fn qr(&self) -> bool {
        self.qr
    }
    pub fn opcode(&self) -> u8 {
        self.opcode
    }
    pub fn aa(&self) -> bool {
        self.aa
    }
    pub fn tc(&self) -> bool {
        self.tc
    }
    pub fn rd(&self) -> bool {
        self.rd
    }
    pub fn ra(&self) -> bool {
        self.ra
    }
    pub fn z(&self) -> u8 {
        self.z
    }
    pub fn rcode(&self) -> u8 {
        self.rcode
    }
    pub fn qdcount(&self) -> u16 {
        self.qdcount
    }
    pub fn ancount(&self) -> u16 {
        self.ancount
    }
    pub fn nscount(&self) -> u16 {
        self.nscount
    }
    pub fn arcount(&self) -> u16 {
        self.arcount
    }
}


#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn parse_one_dns_header() {
        let bytes = [
            0xdb, 0xac, 0x81, 0xa0, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01,
        ];

        let hdr = parse_dns_header(&bytes).unwrap();

        assert_eq!(hdr.id(), 56236);
        assert!(hdr.qr());
        assert_eq!(hdr.opcode(), 0);
        assert_eq!(hdr.aa(), false);
        assert_eq!(hdr.tc(), false);
        assert!(hdr.rd());
        assert!(hdr.ra());
        assert_eq!(hdr.z(), 2);
        assert_eq!(hdr.rcode(), 0);
        assert_eq!(hdr.qdcount(), 1);
        assert_eq!(hdr.ancount(), 2);
        assert_eq!(hdr.nscount(), 0);
        assert_eq!(hdr.arcount(), 1);
    }

    #[test]
    fn rejects_short_header() {
        let bytes = [0u8; 11];
        assert!(parse_dns_header(&bytes).is_err());
    }

}