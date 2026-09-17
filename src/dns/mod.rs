mod header;
mod question;
mod resource_record;
mod full_message;

pub use full_message::{DnsMessage,parse_message};
pub use header::{DnsHeader};
pub use question::{QuestionFormat};
pub use resource_record::RecordFormat;

use std::error::Error;

//helper for parsing
fn be_u16(msg: &[u8], at: usize) -> Result<u16, Box<dyn Error>> {
    let slice = msg.get(at..at + 2).ok_or("slice runs past end of message")?;
    Ok(u16::from_be_bytes(slice.try_into()?))
}

//helper for parsing
fn be_u32(msg: &[u8], at: usize) -> Result<u32, Box<dyn Error>> {
    let slice = msg.get(at..at + 4).ok_or("slice runs past end of message")?;
    Ok(u32::from_be_bytes(slice.try_into()?))
}

//helper for reading QNAME and NAME
pub fn read_name(msg: &[u8], offset: usize) -> Result<(Vec<u8>, usize), Box<dyn Error>> {
    let mut name = vec![];
    let mut current_pos = offset;
    let mut resume: Option<usize> = None;
    let mut ptr_barrier = usize::MAX;

    loop {
        let b = *msg.get(current_pos).ok_or("name runs past end of message")?;
        if b == 0x00 {
            break;
        }
        if b & 0xC0 == 0xC0 {
            if current_pos >=ptr_barrier {
                return Err("pointer cycle detected".into());
            }
            else{ ptr_barrier = current_pos;}

            if resume.is_none() {
                resume = Some(current_pos + 2);
            }

            let b2 = *msg.get(current_pos + 1).ok_or("pointer truncated")? as u16;
            current_pos = (((b as u16) << 8 | b2) & 0x3FFF) as usize;

        } else {
            let length = b as usize;
            let start = current_pos + 1;
            let end = start + length;
            let label = msg.get(start..end).ok_or("label runs past end of message")?;

            if !name.is_empty() {
                name.push(b'.');
            }

            name.extend_from_slice(label);
            current_pos = end;
        }
    }

    Ok((name, resume.unwrap_or(current_pos + 1)))
}


#[cfg(test)]
mod test_support {
    use super::*;

    pub(crate) fn sample_dns_header() -> [u8; 72] {
        let bytes: [u8; 72] = [
            //DNS Header
            0xdb, 0xac, 0x81, 0xa0, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01,
            //Question Section
            0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // Length 7: "example"
            0x03, 0x63, 0x6f, 0x6d, // Length 3: "com"
            0x00, // Null terminator for the name

            //QTYPE and QCLASS
            0x00, 0x01, 0x00, 0x01,
            //Answer Section
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x51, 0x00, 0x04, 0xac, 0x42,
            0x93, 0xf3, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x51, 0x00, 0x04,
            0x68, 0x14, 0x17, 0x9a,
            //Additional Section
            0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        bytes
    }


    #[test]
    fn rejects_self_referential_pointer() {
        let msg = [0xC0, 0x00];
        assert!(read_name(&msg, 0).is_err());
    }

    #[test]
    fn rejects_offset_past_buffer(){
        let msg = [0x01,0x3F, 0xC0, 0x07];

        assert!(read_name(&msg, 0).is_err());
    }

    #[test]
    fn rejects_label_past_length(){
        let msg = [0x12, 0xFF];
        assert!(read_name(&msg, 0).is_err());
    }
    #[test]
    fn rejects_pointer_cycle(){
        let msg = [0x01,0x41,0x01,0x42,0xc0,0x02];
        assert!(read_name(&msg, 0).is_err());
    }
}