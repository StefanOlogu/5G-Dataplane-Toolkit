use crate::gtp::gtpu_header::{GtpHeader, MessageType};
use crate::wire::BoxError;

pub fn dispatch_gtpu<'a>(
    header: &GtpHeader,
    bytes: &'a [u8],
) -> Result<Option<&'a [u8]>, BoxError> {
    match header.message_type() {
        MessageType::GPdu => {
            let start = header.offset();
            let end = 8 + header.length() as usize;
            let tpdu = bytes
                .get(start..end)
                .ok_or("GTP-U T-PDU: length exceeds buffer")?;
            Ok(Some(tpdu))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gtp::gtpu_header::parse_gtpu_header;
    use crate::gtp::tests::{gptu_flag_sample, gptu_no_flag_sample};
    #[test]
    fn dispatch_returns_gpdu() {
        let bytes = gptu_flag_sample();
        let (header, _) = parse_gtpu_header(&bytes).unwrap();
        let answer = dispatch_gtpu(&header, &bytes).unwrap();
        assert_eq!(answer, Some(&[0xDE, 0xAD, 0xBE, 0xEF][..]));
    }

    #[test]
    fn dispatch_returns_none() {
        let mut bytes = gptu_no_flag_sample();
        bytes[1] = 0x01;
        let (header, _) = parse_gtpu_header(&bytes).unwrap();
        let answer = dispatch_gtpu(&header, &bytes).unwrap();
        assert_eq!(answer, None);
    }

    #[test]
    fn dispatch_rejects_incorrect_length() {
        let mut bytes = gptu_flag_sample();
        bytes[3] = 0xFF;
        let (header, _) = parse_gtpu_header(&bytes).unwrap();
        assert!(dispatch_gtpu(&header, &bytes).is_err());
    }
}
