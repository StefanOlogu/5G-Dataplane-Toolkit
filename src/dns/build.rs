use std::error::Error;

pub fn build_query(domain: &str, qtype:u16) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut resulted_bytes = vec![
        0x12, 0x34,//header id
        0x01, //flags high byte
        0x00,//rd,z and rcode
        0x00, 0x01,// qdcount=1
        0x00,0x00,
        0x00,0x00,
        0x00,0x00
    ];

    for label in domain.split('.'){
        if label.len() > 63 {
            return Err("label too long".into());
        }
        let len = label.len();
        resulted_bytes.push(len as u8);
        resulted_bytes.extend_from_slice(label.as_bytes());

    }

    resulted_bytes.push(0x00); // terminator for qname

    resulted_bytes.extend_from_slice(&qtype.to_be_bytes()); // qtype
    resulted_bytes.extend_from_slice(&1u16.to_be_bytes());  // qclass = 1 (IN)

    Ok(resulted_bytes)
}

#[cfg(test)]
mod tests{
    use crate::dns::parse_message;
    use super::*;
    #[test]
    fn round_trip_build_query_to_parse(){
        let bytes = build_query("example.com", 1).unwrap();
        let m = parse_message(&bytes).unwrap();

        assert_eq!(m.header().qr(), false);
        assert!(m.header().rd());
        assert_eq!(m.header().qdcount(), 1);
        assert_eq!(m.header().ancount(), 0);
        assert_eq!(m.questions()[0].qname(), b"example.com");
        assert_eq!(m.questions()[0].qtype(), 1);
        assert_eq!(m.questions()[0].qclass(), 1);
    }
}