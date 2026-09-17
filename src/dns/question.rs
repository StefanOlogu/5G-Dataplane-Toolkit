use std::error::Error;
use crate::dns::{be_u16, read_name};

pub struct QuestionFormat {
    qname:Vec<u8>,
    qtype:u16,
    qclass: u16,
}

pub fn parse_question(bytes: &[u8], offset: usize) -> Result<(QuestionFormat, usize), Box<dyn Error>> {
    let (qname,resume) = read_name(bytes, offset)?;
    let qtype = be_u16(bytes, resume)?;
    let qclass = be_u16(bytes,resume +2)?;

    Ok((QuestionFormat {qname, qtype, qclass}, resume + 4))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_first_question() {
        let msg = crate::dns::test_support::sample_dns_header();
        let (q, resume) = parse_question(&msg, 12).unwrap();
        assert_eq!(q.qname, b"example.com");
        assert_eq!(q.qtype, 1);   // A
        assert_eq!(q.qclass, 1);  // IN
        assert_eq!(resume, 29);
    }

    #[test]
    fn parse_question_name_no_pointer() {
        let bytes = crate::dns::test_support::sample_dns_header();

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
        let bytes = crate::dns::test_support::sample_dns_header();

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