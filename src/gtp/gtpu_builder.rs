use crate::wire::BoxError;

pub fn build_gtpu_header(teid: u32, tpdu: &[u8]) -> Result<Vec<u8>, BoxError> {
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

pub fn write_gtpu_header(teid: u32, payload_len: usize, out: &mut [u8]) -> Result<usize, BoxError>{
    if payload_len > u16::MAX as usize {
        return Err(From::from("T-PDU too large for GTP-U length field"));
    }

    if out.len() < 8{
        return Err(From::from("Output buffer too small for GTP-U header"));
    }

    out[0] = 0x30;
    out[1] = 0xFF;
    out[2..4].copy_from_slice(&(payload_len as u16).to_be_bytes());
    out[4..8].copy_from_slice(&teid.to_be_bytes());
    Ok(8)
}

pub fn build_echo_response(seq_num: u16) -> [u8; 14] {
    let [seq_hi, seq_lo] = seq_num.to_be_bytes();

    [
        0x32,
        0x02,
        0x00, 0x06,
        0x00, 0x00, 0x00, 0x00,
        seq_hi,
        seq_lo,
        0x00,
        0x00,
        0x0E,
        0x00,
    ]
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

    #[test]
    fn write_header_matches_builder() {
        let tpdu = [0xDE, 0xAD, 0xBE, 0xEF];
        let expected = build_gtpu_header(0x11223344, &tpdu).unwrap();

        let mut out = [0u8; 8];
        let n = write_gtpu_header(0x11223344, tpdu.len(), &mut out).unwrap();

        assert_eq!(n, 8);
        assert_eq!(&out[..], &expected[..8]);
    }

    #[test]
    fn write_header_into_headroom_roundtrips() {
        let tpdu = [0xDE, 0xAD, 0xBE, 0xEF];
        let mut buf = [0u8; 8 + 4];
        buf[8..].copy_from_slice(&tpdu);

        write_gtpu_header(0x11223344, tpdu.len(), &mut buf[..8]).unwrap();

        let (header, _) = parse_gtpu_header(&buf).unwrap();
        assert_eq!(header.teid(), 0x11223344);
        assert_eq!(dispatch_gtpu(&header, &buf).unwrap(), Some(&tpdu[..]));
    }

    #[test]
    fn write_header_rejects_small_output() {
        let mut out = [0u8; 7];
        assert!(write_gtpu_header(1, 4, &mut out).is_err());
    }

    #[test]
    fn write_header_rejects_oversized_payload() {
        let mut out = [0u8; 8];
        assert!(write_gtpu_header(1, u16::MAX as usize + 1, &mut out).is_err());
    }

    #[test]
    fn echo_response_exact_bytes() {
        let expected = [
            0x32, 0x02, 0x00, 0x06, // flags (S=1), Echo Response, length 6
            0x00, 0x00, 0x00, 0x00, // TEID 0
            0xAB, 0xCD,             // sequence number
            0x00, 0x00,             // N-PDU, next ext type
            0x0E, 0x00,             // Recovery IE, restart counter 0
        ];
        assert_eq!(build_echo_response(0xABCD), expected);
    }

    #[test]
    fn echo_response_parses_with_own_parser() {
        let resp = build_echo_response(0x0001);
        let (header, _) = parse_gtpu_header(&resp).unwrap();
        assert_eq!(header.message_type(), MessageType::EchoResponse);
        assert_eq!(header.teid(), 0);
    }
}
