use std::convert::TryInto;
use std::error::Error;

//helper for parsing

pub fn be_u8(msg :&[u8], at:usize) -> Result<u8,Box<dyn Error>>{
    let byte = msg.get(at).ok_or("slice runs past end of message")?;
    Ok(*byte)
}

//helper for parsing
pub fn be_u16(msg: &[u8], at: usize) -> Result<u16, Box<dyn Error>> {
    let slice = msg.get(at..at + 2).ok_or("slice runs past end of message")?;
    Ok(u16::from_be_bytes(slice.try_into()?))
}

//helper for parsing
pub fn be_u32(msg: &[u8], at: usize) -> Result<u32, Box<dyn Error>> {
    let slice = msg.get(at..at + 4).ok_or("slice runs past end of message")?;
    Ok(u32::from_be_bytes(slice.try_into()?))
}