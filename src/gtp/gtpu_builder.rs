use std::error::Error;

pub fn build_gtpu_header(teid: u32, tpdu: &[u8]) -> Result<Vec<u8>, Box<dyn Error>>{
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