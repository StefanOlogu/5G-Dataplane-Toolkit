use std::net::Ipv4Addr;
use dataplane::ethernet::parse_ethernet_header;
use dataplane::ip::parse_ipv4_header;
use dataplane::pcap::{parse_global_header, parse_packet_header};
use dataplane::transport::parse_udp_header;

#[test]
fn parse_one_full_packet(){
    let data: &[u8] = &[
        // ---- PCAP global header (24 bytes) ----
        0xD4, 0xC3, 0xB2, 0xA1,  // magic (little-endian)
        0x02, 0x00, 0x04, 0x00,  // version 2.4
        0x00, 0x00, 0x00, 0x00,  // thiszone
        0x00, 0x00, 0x00, 0x00,  // sigfigs
        0xFF, 0xFF, 0x00, 0x00,  // snaplen 65535
        0x01, 0x00, 0x00, 0x00,  // linktype 1 (Ethernet)

        // ---- Packet record header (16 bytes) ----
        0x00, 0x00, 0x00, 0x00,  // ts_sec
        0x00, 0x00, 0x00, 0x00,  // ts_frac
        0x2A, 0x00, 0x00, 0x00,  // incl_len = 42  ← THIS says the packet is 42 bytes
        0x2A, 0x00, 0x00, 0x00,  // orig_len = 42

        // ---- Packet data: exactly 42 bytes (14 Ethernet + 20 IPv4 + 8 UDP) ----
        // Ethernet (14)
        0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,  // dest MAC
        0x11,0x22,0x33,0x44,0x55,0x66,  // src MAC
        0x08, 0x00,                     // ethertype 0x0800 = IPv4
        // IPv4 (20)
        0x45,                           // version 4, IHL 5
        0x00,                           // TOS
        0x00, 0x1C,                     // total_length = 28 (20 IP + 8 UDP)
        0x00, 0x00,                     // identification
        0x00, 0x00,                     // flags + fragment
        0x40,                           // TTL 64
        0x11,                           // protocol 17 = UDP
        0x00, 0x00,                     // checksum (fake, we don't verify)
        0xC0,0xA8,0x00,0x01,            // src IP 192.168.0.1
        0xC0,0xA8,0x00,0x02,            // dst IP 192.168.0.2
        // UDP (8)
        0xB3, 0x6B,                     // src port 45931
        0x01, 0xBB,                     // dst port 443
        0x00, 0x08,                     // length 8
        0x00, 0x00,                     // checksum (fake)
    ];

    let global = parse_global_header(data).unwrap();
    assert_eq!(global.snaplen(),65535);

    //packet record start after the 24-byte header
    let packet = parse_packet_header(&data[24..40],global.big_endian()).unwrap();
    assert_eq!(packet.incl_len(),42);

    //packet data starts at 40 (24 header + 16 packet) and runs incl_len bytes
    let payload = &data[40..40 + packet.incl_len() as usize];

    let ethernet = parse_ethernet_header(payload).unwrap();
    assert_eq!(ethernet.src_mac(),&[0x11,0x22,0x33,0x44,0x55,0x66]);
    assert_eq!(ethernet.dest_mac(),&[0xAA,0xBB,0xCC,0xDD,0xEE,0xFF]);
    assert_eq!(ethernet.ether_type(),0x0800);

    let ip_payload = &payload[14..];
    let ipv4 = parse_ipv4_header(ip_payload).unwrap();
    assert_eq!(ipv4.version(),4);
    assert_eq!(ipv4.ihl(),5);
    assert_eq!(ipv4.header_length(),20);
    assert_eq!(ipv4.total_length(),28);
    assert_eq!(ipv4.ttl(),64);
    assert_eq!(ipv4.protocol(),17);
    assert_eq!(ipv4.src_ip(),&Ipv4Addr::new(192,168,0,1));
    assert_eq!(ipv4.dest_ip(),&Ipv4Addr::new(192,168,0,2));

    let start = ipv4.header_length() as usize;
    let end = (ipv4.total_length() as usize).min(ip_payload.len());
    let transport_payload = &ip_payload[start..end];

    let transport = parse_udp_header(transport_payload).unwrap();
    assert_eq!(transport.src_port(),45931);
    assert_eq!(transport.dest_port(),443);
    assert_eq!(transport.length(),8);
}