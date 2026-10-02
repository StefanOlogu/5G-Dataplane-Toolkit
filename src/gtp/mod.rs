mod gtpu_header;

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn gptu_no_flag_sample() -> [u8; 12] {
        let bytes: [u8;12] = [
            0x30, //flags
            0xFF, //message type
            0x00, 0x04, // length
            0x11, 0x22, 0x33, 0x44, //TEID
            0xDE, 0xAD, 0xBE, 0xEF //inner packet
        ];
        bytes
    }

    pub(crate) fn gptu_flag_sample() -> [u8; 16] {
        let bytes: [u8;16] =[
            0x32, //flags
            0xFF, //message type
            0x00, 0x08, //length
            0x11, 0x22, 0x33, 0x44, //TEID
            0x00, 0x07, // sequence number
            0x00, // N-PDU Number
            0x00, // next extension header
            0xDE, 0xAD, 0xBE, 0xEF //inner packet
        ];
        bytes
    }
}