use std::error::Error;
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

pub struct QuestionFormat {
    qname:Vec<u8>,
    qtype:u16,
    qclass: u16,
}

pub struct DnsMessage {
    header: DnsHeader,
    questions: Vec<QuestionFormat>,
    answers: Vec<RecordFormat>,
    authorities: Vec<RecordFormat>,
    additionals: Vec<RecordFormat>,
}

pub struct RecordFormat {
    name:Vec<u8>,
    record_type:u16,
    class: u16,
    ttl: u32,
    rdlength: u16,
    rdata: Vec<u8>,
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
                return Err("pointer cycle detected".into());
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

pub fn parse_question(bytes: &[u8], offset: usize) -> Result<(QuestionFormat, usize), Box<dyn Error>> {
    let (qname,resume) = read_name(bytes, offset)?;
    let qtype_slice = bytes.get(resume..resume+2).ok_or("question type is missing bytes")?;
    let qtype = u16::from_be_bytes(qtype_slice.try_into()?);
    let qclass_slice = bytes.get(resume+2..resume+4).ok_or("question class is missing bytes")?;
    let qclass = u16::from_be_bytes(qclass_slice.try_into()?);

    Ok((QuestionFormat {qname, qtype, qclass}, resume + 4))
}

pub fn parse_record(bytes : &[u8], offset:usize) -> Result<(RecordFormat, usize), Box<dyn Error>> {
    let (name,resume_from_name) = read_name(bytes, offset)?;
    let type_slice = bytes.get(resume_from_name..resume_from_name+2).ok_or("type is missing bytes")?;
    let record_type = u16::from_be_bytes(type_slice.try_into()?);
    let class_slice = bytes.get(resume_from_name+2..resume_from_name+4).ok_or("class is missing bytes")?;
    let class = u16::from_be_bytes(class_slice.try_into()?);
    let ttl_slice = bytes.get(resume_from_name+4..resume_from_name+8).ok_or("ttl is missing bytes")?;
    let ttl = u32::from_be_bytes(ttl_slice.try_into()?);
    let rdlength_slice = bytes.get(resume_from_name+8..resume_from_name+10).ok_or("rdlength is missing bytes")?;
    let rdlength = u16::from_be_bytes(rdlength_slice.try_into()?);
    let rdata_slice = bytes.get(resume_from_name+10..resume_from_name+ 10 +rdlength as usize).ok_or("rdata is missing bytes")?;
    let rdata = rdata_slice.to_vec();

    Ok((RecordFormat{
        name,
        record_type,
        class,
        ttl,
        rdlength,
        rdata
    },resume_from_name +10 + rdlength as usize))
}

pub fn parse_message(bytes: &[u8]) -> Result<DnsMessage, Box<dyn Error>> {
    let header = parse_dns_header(bytes)?;
    let mut offset = 12;
    let mut questions : Vec<QuestionFormat> = vec![];
    let mut answers : Vec<RecordFormat> = vec![];
    let mut authorities : Vec<RecordFormat> = vec![];
    let mut additionals : Vec<RecordFormat> = vec![];

    for _ in 0..header.qdcount {
        let (current_question,  current_offset) = parse_question(bytes, offset)?;
        questions.push(current_question);
        offset = current_offset;
    }

    for _ in 0..header.ancount {
        let (current_answer, current_offset) = parse_record(bytes, offset)?;
        answers.push(current_answer);
        offset = current_offset;
    }

    for _ in 0..header.nscount {
        let (current_authority, current_offset) = parse_record(bytes, offset)?;
        authorities.push(current_authority);
        offset = current_offset;
    }

    for _ in 0..header.arcount {
        let (current_authority, current_offset) = parse_record(bytes, offset)?;
        additionals.push(current_authority);
        offset = current_offset;
    }

    Ok(DnsMessage{
        header,
        questions,
        answers,
        authorities,
        additionals,
    })
}

impl DnsMessage{
    pub fn header(&self) -> &DnsHeader {
        &self.header
    }
    pub fn questions(&self) -> &Vec<QuestionFormat> {
        &self.questions
    }
    pub fn answers(&self) -> &Vec<RecordFormat> {
        &self.answers
    }
    pub fn authorities(&self) -> &Vec<RecordFormat> {
        &self.authorities
    }
    pub fn additionals(&self) -> &Vec<RecordFormat> {
        &self.additionals
    }
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

impl QuestionFormat {
    pub fn qname(&self) -> &Vec<u8> {
        &self.qname
    }
    pub fn qtype(&self) -> u16 {
        self.qtype
    }
    pub fn qclass(&self) -> u16 {
        self.qclass
    }
}

impl RecordFormat {
    pub fn name(&self) -> &Vec<u8> {
        &self.name
    }
    pub fn record_type(&self) -> u16 {
        self.record_type
    }
    pub fn class(&self) -> u16 {
        self.class
    }
    pub fn ttl(&self) -> u32 {
        self.ttl
    }
    pub fn rdlength(&self) -> u16 {
        self.rdlength
    }
    pub fn rdata(&self) -> &Vec<u8> {
        &self.rdata
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
    fn parse_full_message() {
        let msg = sample_dns_header();
        let m = parse_message(&msg).unwrap();

        assert_eq!(m.header.id, 56236);
        assert_eq!(m.questions.len(), 1);
        assert_eq!(m.answers.len(), 2);
        assert_eq!(m.authorities.len(), 0);
        assert_eq!(m.additionals.len(), 1);

        assert_eq!(m.questions[0].qname, b"example.com");
        assert_eq!(m.answers[0].rdata, [0xac, 0x42, 0x93, 0xf3]);
        assert_eq!(m.answers[1].rdata, [0x68, 0x14, 0x17, 0x9a]);
        assert_eq!(m.additionals[0].record_type, 41);  // OPT = 41
    }

    #[test]
    fn parse_two_answer_records() {
        let msg = sample_dns_header();

        let (rr1, r1) = parse_record(&msg, 29).unwrap();
        assert_eq!(rr1.name, b"example.com");
        assert_eq!(rr1.record_type, 1);              // A
        assert_eq!(rr1.class, 1);                     // IN
        assert_eq!(rr1.rdlength, 4);
        assert_eq!(rr1.rdata, [0xac, 0x42, 0x93, 0xf3]);
        assert_eq!(r1, 45);

        let (rr2, r2) = parse_record(&msg, r1).unwrap();
        assert_eq!(rr2.rdata, [0x68, 0x14, 0x17, 0x9a]);
        assert_eq!(r2, 61);
    }

    #[test]
    fn parse_first_question() {
        let msg = sample_dns_header();
        let (q, resume) = parse_question(&msg, 12).unwrap();
        assert_eq!(q.qname, b"example.com");
        assert_eq!(q.qtype, 1);   // A
        assert_eq!(q.qclass, 1);  // IN
        assert_eq!(resume, 29);
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

    #[test]
    fn rejects_self_referential_pointer() {
        let msg = [0xC0, 0x00];
        assert!(read_name(&msg, 0).is_err());
    }

    #[test]
    fn rejects_offset_past_buffer(){
        let msg = [0x01,0x3F, 0xC0, 0x07];

        assert!(read_name(&msg, 0).is_err());
    }

    #[test]
    fn rejects_label_past_length(){
        let msg = [0x12, 0xFF];
        assert!(read_name(&msg, 0).is_err());
    }
    #[test]
    fn rejects_pointer_cycle(){
        let msg = [0x01,0x41,0x01,0x42,0xc0,0x02];
        assert!(read_name(&msg, 0).is_err());
    }
}