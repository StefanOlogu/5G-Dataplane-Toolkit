use std::error::Error;
use crate::dns::header::{DnsHeader, parse_dns_header};
use crate::dns::question::{QuestionFormat, parse_question};
use crate::dns::resource_record::{RecordFormat, parse_record};

pub struct DnsMessage {
    header: DnsHeader,
    questions: Vec<QuestionFormat>,
    answers: Vec<RecordFormat>,
    authorities: Vec<RecordFormat>,
    additionals: Vec<RecordFormat>,
}

pub fn parse_message(bytes: &[u8]) -> Result<DnsMessage, Box<dyn Error>> {
    let header = parse_dns_header(bytes)?;
    let mut offset = 12;
    let mut questions : Vec<QuestionFormat> = vec![];
    let mut answers : Vec<RecordFormat> = vec![];
    let mut authorities : Vec<RecordFormat> = vec![];
    let mut additionals : Vec<RecordFormat> = vec![];

    for _ in 0..header.qdcount() {
        let (current_question,  current_offset) = parse_question(bytes, offset)?;
        questions.push(current_question);
        offset = current_offset;
    }

    for _ in 0..header.ancount() {
        let (current_answer, current_offset) = parse_record(bytes, offset)?;
        answers.push(current_answer);
        offset = current_offset;
    }

    for _ in 0..header.nscount() {
        let (current_authority, current_offset) = parse_record(bytes, offset)?;
        authorities.push(current_authority);
        offset = current_offset;
    }

    for _ in 0..header.arcount() {
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

#[cfg(test)]
mod tests {
    use crate::dns::test_support::sample_dns_header;
    use super::*;

    #[test]
    fn parse_full_message() {
        let msg = sample_dns_header();
        let m = parse_message(&msg).unwrap();

        assert_eq!(m.header.id(), 56236);
        assert_eq!(m.questions.len(), 1);
        assert_eq!(m.answers.len(), 2);
        assert_eq!(m.authorities.len(), 0);
        assert_eq!(m.additionals.len(), 1);

        assert_eq!(m.questions[0].qname(), b"example.com");
        assert_eq!(*m.answers[0].rdata(), [0xac, 0x42, 0x93, 0xf3]);
        assert_eq!(*m.answers[1].rdata(), [0x68, 0x14, 0x17, 0x9a]);
        assert_eq!(m.additionals[0].record_type(), 41);  // OPT = 41
    }
}