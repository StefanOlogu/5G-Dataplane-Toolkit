use crate::gtp::extension_walker::extension_walker;
use crate::wire::{be_u8, be_u16, be_u32, BoxError};
use std::error::Error;

pub struct GtpHeader {
    offset: usize,
    e: bool,
    s: bool,
    pn: bool,
    message_type: MessageType,
    length: u16,
    teid: u32,
    seq_num: Option<u16>,
    npdu_num: Option<u8>,
    next_extension_header_type: Option<u8>,
}
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MessageType {
    Request,
    Response,
    ErrorIndication,
    HeaderExtension,
    EndMarker,
    GPdu,
    Unknown(u8),
}

pub fn parse_gtpu_header(bytes: &[u8]) -> Result<(GtpHeader, usize), BoxError> {
    let first_byte = be_u8(bytes, 0)?;
    let version = (first_byte & 0xE0) >> 5;
    if version != 1 {
        return Err(From::from("Unsupported GTP-U version"));
    }

    let pt = (first_byte & 0x10) >> 4;
    if pt != 1 {
        return Err(From::from("GTP' detected instead of GTP"));
    }

    let e = (first_byte & 0x04) != 0;
    let s = (first_byte & 0x02) != 0;
    let pn = (first_byte & 0x01) != 0;

    let offset = if e {
        extension_walker(bytes)?
    } else if s || pn {
        12
    } else {
        8
    };

    let message_type = MessageType::from(be_u8(bytes, 1)?);

    let length = be_u16(bytes, 2).map_err(|e| format!("GTP-U Length: {e}"))?;
    let teid = be_u32(bytes, 4).map_err(|e| format!("GTP-U Teid: {e}"))?;

    let (seq_num, npdu_num, next_extension_header_type) = if e || s || pn {
        let mut seq_num = None;
        if s {
            seq_num = Some(be_u16(bytes, 8).map_err(|e| format!("GTP-U Sequence Number: {e}"))?);
        }

        let mut npdu_num = None;
        if pn {
            npdu_num = Some(be_u8(bytes, 10)?);
        }

        let mut next_extension_header_type = None;
        if e {
            next_extension_header_type = Some(be_u8(bytes, 11)?);
        }
        (seq_num, npdu_num, next_extension_header_type)
    } else {
        (None, None, None)
    };

    Ok((
        GtpHeader {
            offset,
            e,
            s,
            pn,
            message_type,
            length,
            teid,
            seq_num,
            npdu_num,
            next_extension_header_type,
        },
        offset,
    ))
}

impl GtpHeader {
    pub fn offset(&self) -> usize {
        self.offset
    }
    pub fn e(&self) -> bool {
        self.e
    }
    pub fn s(&self) -> bool {
        self.s
    }
    pub fn pn(&self) -> bool {
        self.pn
    }
    pub fn message_type(&self) -> MessageType {
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

impl From<u8> for MessageType {
    fn from(n: u8) -> Self {
        match n {
            1 => MessageType::Request,
            2 => MessageType::Response,
            26 => MessageType::ErrorIndication,
            31 => MessageType::HeaderExtension,
            254 => MessageType::EndMarker,
            255 => MessageType::GPdu,
            other => MessageType::Unknown(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gtp::tests::{gptu_flag_sample, gptu_no_flag_sample};

    #[test]
    fn gtpu_happy_path() {
        let bytes = gptu_no_flag_sample();
        let (header, offset) = parse_gtpu_header(&bytes).unwrap();
        assert_eq!(header.teid(), 287454020);
        assert_eq!(header.length(), 4);
        assert_eq!(header.message_type(), MessageType::GPdu);
        assert!(!header.e());
        assert!(!header.pn());
        assert!(!header.s());
        assert_eq!(offset, 8);

        let bytes = gptu_flag_sample();
        let (header, offset) = parse_gtpu_header(&bytes).unwrap();
        assert_eq!(header.seq_num(), Some(7));
        assert_eq!(header.npdu_num(), None);
        assert_eq!(header.next_extension_header_type(), None);
        assert_eq!(offset, 12);
    }

    #[test]
    fn gtpu_truncated() {
        let full = gptu_no_flag_sample();
        assert!(parse_gtpu_header(&full[..6]).is_err());
    }
}
