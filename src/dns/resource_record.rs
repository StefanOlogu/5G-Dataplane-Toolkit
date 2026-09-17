use std::error::Error;
use crate::dns::{be_u16, be_u32, read_name};

pub struct RecordFormat {
    name:Vec<u8>,
    record_type:u16,
    class: u16,
    ttl: u32,
    rdlength: u16,
    rdata: Vec<u8>,
}

pub fn parse_record(bytes : &[u8], offset:usize) -> Result<(RecordFormat, usize), Box<dyn Error>> {
    let (name,resume_from_name) = read_name(bytes, offset)?;
    let record_type = be_u16(bytes,resume_from_name)?;
    let class = be_u16(bytes,resume_from_name +2)?;
    let ttl = be_u32(bytes,resume_from_name +4)?;
    let rdlength = be_u16(bytes,resume_from_name +8)?;
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
    use crate::dns::test_support::sample_dns_header;
    use super::*;

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
}

