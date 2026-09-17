use std::error::Error;
//TODO:read_name pointer safety tests
//HEX STREAM USED:dbac81a00001000200000001076578616d706c6503636f6d0000010001c00c00010001000000510004ac4293f3c00c000100010000005100046814179a00002904d0000000000000

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

pub fn read_name(msg: &[u8], offset: usize) -> Result<(Vec<u8>, usize), Box<dyn Error>> {
    let mut name = vec![];
    let mut current_pos = offset;
    let mut resume: Option<usize> = None;
    let mut ptr_barrier = usize::MAX;

    loop {
        let b = *msg.get(current_pos).ok_or("name runs past end of message")?;
        if b == 0x00 {
            break;
        }
        if b & 0xC0 == 0xC0 {
            if current_pos >=ptr_barrier {
                Err("infinite loop detected")?;
            }
            else{ ptr_barrier = current_pos;}

            if resume.is_none() {
                resume = Some(current_pos + 2);
            }

            let b2 = *msg.get(current_pos + 1).ok_or("pointer truncated")? as u16;
            current_pos = (((b as u16) << 8 | b2) & 0x3FFF) as usize;

        } else {
            let length = b as usize;
            let start = current_pos + 1;
            let end = start + length;
            let label = msg.get(start..end).ok_or("label runs past end of message")?;

            if !name.is_empty() {
                name.push(b'.');
            }

            name.extend_from_slice(label);
            current_pos = end;
        }
    }

    Ok((name, resume.unwrap_or(current_pos + 1)))
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

    fn sample_dns_header() -> [u8; 72] {
        let bytes: [u8; 72] = [
            //DNS Header
            0xdb, 0xac, 0x81, 0xa0, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01,
            //Question Section
            0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // Length 7: "example"
            0x03, 0x63, 0x6f, 0x6d, // Length 3: "com"
            0x00, // Null terminator for the name

            //QTYPE and QCLASS
            0x00, 0x01, 0x00, 0x01,
            //Answer Section
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x51, 0x00, 0x04, 0xac, 0x42,
            0x93, 0xf3, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x51, 0x00, 0x04,
            0x68, 0x14, 0x17, 0x9a,
            //Additional Section
            0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        bytes
    }

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

    #[test]
    fn parse_question_name_no_pointer() {
        let bytes = sample_dns_header();

        let (name, resume) = read_name(&bytes, 12).unwrap();

        assert_eq!(
            name,
            [
                0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d
            ]
        );
        assert_eq!(resume, 25);
    }

    #[test]
    fn parse_question_name_with_pointer() {
        let bytes = sample_dns_header();

        let (name, resume) = read_name(&bytes, 29).unwrap();

        assert_eq!(
            name,
            [
                0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d
            ]
        );
        assert_eq!(resume, 31);
    }
}
