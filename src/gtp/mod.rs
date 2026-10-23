mod dispatch;
mod extension_walker;
mod gtpu_builder;
mod gtpu_header;

pub use dispatch::*;
pub use gtpu_header::*;
pub use gtpu_builder::*;

#[cfg(test)]
mod tests {

    pub(crate) fn gptu_no_flag_sample() -> [u8; 12] {
        let bytes: [u8; 12] = [
            0x30, //flags
            0xFF, //message type
            0x00, 0x04, // length
            0x11, 0x22, 0x33, 0x44, //TEID
            0xDE, 0xAD, 0xBE, 0xEF, //inner packet
        ];
        bytes
    }

    pub(crate) fn gptu_flag_sample() -> [u8; 16] {
        let bytes: [u8; 16] = [
            0x32, //flags
            0xFF, //message type
            0x00, 0x08, //length
            0x11, 0x22, 0x33, 0x44, //TEID
            0x00, 0x07, // sequence number
            0x00, // N-PDU Number
            0x00, // next extension header
            0xDE, 0xAD, 0xBE, 0xEF, //inner packet
        ];
        bytes
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    pub fn gpdu(teid: u32, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x30, 0xFF];
        p.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        p.extend_from_slice(&teid.to_be_bytes());
        p.extend_from_slice(payload);
        p
    }

    pub fn echo_request(seq: u16) -> Vec<u8> {
        let mut p = vec![0x32, 0x01, 0x00, 0x04, 0, 0, 0, 0];
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&[0x00, 0x00]); // N-PDU, next ext type
        p
    }
}
