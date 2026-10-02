
use std::error::Error;
use crate::wire::{be_u16, be_u32, be_u8};

pub struct GtpHeader {
    e:bool,
    s:bool,
    pn:bool,
    message_type:u8,
    length:u16,
    teid:u32,
    seq_num:Option<u16>,
    npdu_num:Option<u8>,
    next_extension_header_type:Option<u8>,
}

pub fn parse_gtpu_header(bytes:&[u8]) ->Result<(GtpHeader,usize), Box<dyn Error>> {

    let first_byte = be_u8(bytes,0)?;
    let version = (first_byte & 0xE0) >> 5;
    if version != 1 {
        return Err(From::from("Unsupported GTP-U version"));
    }

    let pt = (first_byte & 0x10) >> 4;
    if pt != 1 {
        return Err(From::from("GTP' detected instead of GTP"));
    }

    let e = (first_byte & 0x04)!=0;

    if e{
        return Err(From::from("Dont cover extensions for now"));
    }

    let s = (first_byte & 0x02) !=0;
    let pn = (first_byte & 0x01) !=0;

    let message_type = be_u8(bytes, 1)?;
    let length =be_u16(bytes,2).map_err(|e| format!("GTP-U Length: {e}"))?;
    let teid = be_u32(bytes,4).map_err(|e| format!("GTP-U Teid: {e}"))?;


    let (seq_num,npdu_num,next_extension_header_type,offset) = if e || s || pn {
        let mut seq_num = None;
        if s{
            seq_num = Some(be_u16(bytes,8).map_err(|e| format!("GTP-U Sequence Number: {e}"))?);
        }

        let mut npdu_num = None;
        if pn {
            npdu_num = Some(be_u8(bytes, 10)?);
        }

        let mut next_extension_header_type = None;
        if e{

            next_extension_header_type = Some(be_u8(bytes,11)?);
        }
        (seq_num,npdu_num,next_extension_header_type, 12usize)
    }
    else{
        (None,None,None, 8usize)
    };

    Ok((GtpHeader{
        e,
        s,
        pn,
        message_type,
        length,
        teid,
        seq_num,
        npdu_num,
        next_extension_header_type
    }, offset))
}

impl GtpHeader {
    pub fn e(&self) -> bool {
        self.e
    }
    pub fn s(&self) -> bool {
        self.s
    }
    pub fn pn(&self) -> bool {
        self.pn
    }
    pub fn message_type(&self) -> u8 {
        self.message_type
    }
    pub fn length(&self) -> u16 {
        self.length
    }
    pub fn teid(&self) -> u32 {
        self.teid
    }
    pub fn seq_num(&self) -> Option<u16> {
        self.seq_num
    }
    pub fn npdu_num(&self) -> Option<u8> {
        self.npdu_num
    }
    pub fn next_extension_header_type(&self) -> Option<u8> {
        self.next_extension_header_type
    }
}

#[cfg(test)]
mod tests {
    use crate::gtp::tests::{gptu_flag_sample, gptu_no_flag_sample};
    use super::*;

    #[test]
    fn gtpu_happy_path() {
        let bytes = gptu_no_flag_sample();
        let (header,offset) = parse_gtpu_header(&bytes).unwrap();
        assert_eq!(header.teid(),287454020);
        assert_eq!(header.length(),4);
        assert_eq!(header.message_type(),255);
        assert!(!header.e());
        assert!(!header.pn());
        assert!(!header.s());
        assert_eq!(offset,8);

        let bytes = gptu_flag_sample();
        let (header, offset) = parse_gtpu_header(&bytes).unwrap();
        assert_eq!(header.seq_num(), Some(7));
        assert_eq!(header.npdu_num(), None);
        assert_eq!(header.next_extension_header_type(), None);
        assert_eq!(offset, 12);
    }

    #[test]
    fn gtpu_truncated(){
        let full = gptu_no_flag_sample();
        assert!(parse_gtpu_header(&full[..6]).is_err());
    }

    #[test]
    fn gtpu_e_flag_rejection(){
        let bytes = [0x36, 0xFF, 0x00, 0x06, 0x11, 0x22, 0x33, 0x44, 0x00, 0x07, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
        assert!(parse_gtpu_header(&bytes).is_err());
    }
}