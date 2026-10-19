use std::error::Error;

pub fn build_gtpu_header(teid: u32, tpdu: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    if tpdu.len() > u16::MAX as usize {
        return Err(From::from("T-PDU too large for GTP-U length field"));
    }
    let length = tpdu.len() as u16;

    let mut buf = Vec::new();
    buf.push(0x30);
    buf.push(0xFF);
    buf.extend_from_slice(&length.to_be_bytes());
    buf.extend_from_slice(&teid.to_be_bytes());
    buf.extend_from_slice(tpdu);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gtp::dispatch::dispatch_gtpu;
    use crate::gtp::gtpu_header::{MessageType, parse_gtpu_header};

    #[test]
    fn roundtrip_builder_to_parser_gtpu() {
        let tpdu = [0xDE, 0xAD, 0xBE, 0xEF];
        let frame = build_gtpu_header(0x11223344, &tpdu).unwrap();
        let (header, _) = parse_gtpu_header(&frame).unwrap();
        assert_eq!(header.teid(), 0x11223344);
        assert_eq!(header.message_type(), MessageType::GPdu);
        assert_eq!(dispatch_gtpu(&header, &frame).unwrap(), Some(&tpdu[..]));
    }
}
