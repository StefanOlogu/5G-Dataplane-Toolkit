use crate::gtp::{build_echo_response, dispatch_gtpu, parse_gtpu_header,MessageType, DL_HEADER_LEN, write_gtpu_dl_header};
use crate::upf::table::SessionTable;
use crate::wire::BoxError;
use std::net::{Ipv4Addr, SocketAddr};

#[derive(Debug)]
pub enum UplinkAction<'a> {
    Forward { dst: SocketAddr, payload: &'a [u8] },
    Reply { dst: SocketAddr, datagram : [u8;14]},
    Drop(UplinkDropReason),
}

#[derive(Debug)]
pub enum UplinkDropReason {
    Malformed(BoxError),
    NotGpdu(MessageType),
    UnknownTeid(u32),
}

pub const HEADROOM: usize = 16;
const _: () = assert!(HEADROOM >= DL_HEADER_LEN);

#[derive(Debug)]
pub enum DownlinkAction<'a> {
    Forward { dst: SocketAddr, datagram: &'a [u8] },
    Drop(DownlinkDropReason),
}

#[derive(Debug)]
pub enum DownlinkDropReason {
    NotIpv4,
    UnknownUe(Ipv4Addr),
    Encap(BoxError),
}

pub fn handle_downlink<'a>(table: &SessionTable, buf: &'a mut [u8], n: usize) -> DownlinkAction<'a>{
    let packet= match buf.get(HEADROOM.. HEADROOM + n){
        Some(packet) => packet,
        None => return DownlinkAction::Drop(DownlinkDropReason::NotIpv4),
    };

    if packet.len() < 20 || packet[0] >> 4 != 4{
        return DownlinkAction::Drop(DownlinkDropReason::NotIpv4)
    }

    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

    let session = match table.lookup_downlink(dst_ip){
        Some(session) => session,
        None => return DownlinkAction::Drop(DownlinkDropReason::UnknownUe(dst_ip)),
    };

    match write_gtpu_dl_header(session.dl_teid, session.qfi, n, &mut buf[HEADROOM - DL_HEADER_LEN..HEADROOM]) {
        Ok(_) => DownlinkAction::Forward {
            dst: session.gnb, datagram: &buf[HEADROOM - DL_HEADER_LEN..HEADROOM + n]
        },
        Err(e) => DownlinkAction::Drop(DownlinkDropReason::Encap(e)),
    }

}

pub fn handle_uplink<'a>(table: &SessionTable, buf: &'a [u8], src: SocketAddr) -> UplinkAction<'a> {
    let (header, _) = match parse_gtpu_header(buf) {
        Ok(header) => header,

        Err(e) => return UplinkAction::Drop(UplinkDropReason::Malformed(e)),
    };

    if header.message_type() == MessageType::EchoRequest {
        let Some(seq) = header.seq_num() else {
            return UplinkAction::Drop(UplinkDropReason::Malformed(
                "Echo Request without sequence number".into(),
            ));
        };
        return UplinkAction::Reply {
            dst: src,
            datagram: build_echo_response(seq),
        };
    }

    let tpdu = match dispatch_gtpu(&header, buf) {
        Ok(Some(tpdu)) => tpdu,
        Ok(None) => return UplinkAction::Drop(UplinkDropReason::NotGpdu(header.message_type())),
        Err(e) => return UplinkAction::Drop(UplinkDropReason::Malformed(e)),
    };

    let Some(session) = table.lookup_uplink(header.teid()) else {
        return UplinkAction::Drop(UplinkDropReason::UnknownTeid(header.teid()));
    };

    UplinkAction::Forward {
        dst: session.n6_peer,
        payload: tpdu,
    }
}

#[cfg(test)]
mod tests {
    use crate::gtp::build_echo_response;
    use super::*;
    use crate::gtp::fixtures::{echo_request, gpdu};
    use crate::upf::Session;

    const TEID: u32 = 0x1234_5678;

    fn src() -> SocketAddr {
        "10.0.0.1:2152".parse().unwrap()
    }

    fn sink() -> SocketAddr {
        "127.0.0.1:9000".parse().unwrap()
    }

    fn session(ul_teid: u32, n6_peer: SocketAddr) -> Session {
        Session {
            ue_ip: "10.45.0.2".parse().unwrap(),
            ul_teid,
            dl_teid: 0x0000_0001,
            gnb: "10.0.0.2:1000".parse().unwrap(),
            n6_peer,
            qfi:9,
        }
    }
    fn table_with(teid: u32, n6_peer: SocketAddr) -> SessionTable {
        let mut t = SessionTable::new();
        t.insert(session(teid, n6_peer)).unwrap();
        t
    }

    #[test]
    fn forwards_gpdu_with_known_teid() {
        let buf = gpdu(TEID, &[1, 2, 3, 4]);
        let table = table_with(TEID, sink());

        let action = handle_uplink(&table, &buf, src());

        let UplinkAction::Forward { dst, payload } = action else {
            panic!("expected Forward, got {action:?}");
        };
        assert_eq!(dst, sink());
        assert_eq!(payload, &[1u8, 2, 3, 4][..]);
        assert!(buf.as_ptr_range().contains(&payload.as_ptr()));
    }

    #[test]
    fn forwards_payload_after_extension_chain() {
        let mut buf = vec![0x34, 0xFF, 0x00, 0x0C];
        buf.extend_from_slice(&TEID.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x85]);
        buf.extend_from_slice(&[0x01, 0x00, 0x09, 0x00]);
        buf.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        let table = table_with(TEID, sink());

        let action = handle_uplink(&table, &buf, src());

        let UplinkAction::Forward { payload, .. } = action else {
            panic!("expected Forward, got {action:?}");
        };
        assert_eq!(payload, &[0xAAu8, 0xBB, 0xCC, 0xDD][..]);
    }

    #[test]
    fn drops_unknown_teid() {
        let buf = gpdu(TEID, &[1, 2, 3, 4]);
        let table = table_with(0xDEAD_BEEF, sink());

        let action = handle_uplink(&table, &buf, src());

        assert!(
            matches!(action, UplinkAction::Drop(UplinkDropReason::UnknownTeid(t)) if t == TEID),
            "got {action:?}"
        );
    }

    #[test]
    fn drops_when_length_field_exceeds_buffer() {
        let mut buf = gpdu(TEID, &[1, 2, 3, 4]);
        buf.truncate(buf.len() - 2);
        let table = table_with(TEID, sink());

        let action = handle_uplink(&table, &buf, src());

        assert!(
            matches!(action, UplinkAction::Drop(UplinkDropReason::Malformed(_))),
            "got {action:?}"
        );
    }

    #[test]
    fn drops_truncated_header() {
        let buf = gpdu(TEID, &[1, 2, 3, 4]);
        let table = table_with(TEID, sink());

        let action = handle_uplink(&table, &buf[..5], src());

        assert!(
            matches!(action, UplinkAction::Drop(UplinkDropReason::Malformed(_))),
            "got {action:?}"
        );
    }

    #[test]
    fn drops_empty_buffer() {
        let table = table_with(TEID, sink());

        let action = handle_uplink(&table, &[], src());

        assert!(
            matches!(action, UplinkAction::Drop(UplinkDropReason::Malformed(_))),
            "got {action:?}"
        );
    }

    #[test]
    fn zero_length_tpdu_behavior() {
        let buf = gpdu(TEID, &[]);
        let table = table_with(TEID, sink());

        let action = handle_uplink(&table, &buf, src());

        let UplinkAction::Forward { payload, .. } = action else {
            panic!("expected Forward with empty payload, got {action:?}");
        };
        assert!(payload.is_empty());
    }

    fn ipv4_packet(dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[16..20].copy_from_slice(&dst.octets());
        p.extend_from_slice(payload);
        p
    }

    fn downlink_buf(packet: &[u8]) -> (Vec<u8>, usize) {
        let mut buf = vec![0u8; HEADROOM];
        buf.extend_from_slice(packet);
        (buf, packet.len())
    }

    fn ue_ip() -> Ipv4Addr {
        "10.45.0.2".parse().unwrap()
    }

    #[test]
    fn downlink_encapsulates_for_known_ue() {
        let packet = ipv4_packet(ue_ip(), &[1, 2, 3, 4]);
        let (mut buf, n) = downlink_buf(&packet);
        let table = table_with(TEID, sink());

        let action = handle_downlink(&table, &mut buf, n);

        let DownlinkAction::Forward { dst, datagram } = action else {
            panic!("expected Forward, got {action:?}");
        };
        assert_eq!(dst, "10.0.0.2:1000".parse::<SocketAddr>().unwrap());
        assert_eq!(datagram.len(), DL_HEADER_LEN + n);
        assert_eq!(datagram[14], 9); //QFI check

        let (header, _) = parse_gtpu_header(datagram).unwrap();
        assert_eq!(header.teid(), 0x0000_0001);
        assert_eq!(dispatch_gtpu(&header, datagram).unwrap(), Some(&packet[..]));
    }

    #[test]
    fn downlink_drops_unknown_ue() {
        let other: Ipv4Addr = "10.45.0.99".parse().unwrap();
        let (mut buf, n) = downlink_buf(&ipv4_packet(other, &[1, 2]));
        let table = table_with(TEID, sink());

        let action = handle_downlink(&table, &mut buf, n);

        assert!(
            matches!(action, DownlinkAction::Drop(DownlinkDropReason::UnknownUe(ip)) if ip == other),
            "got {action:?}"
        );
    }

    #[test]
    fn downlink_drops_ipv6() {
        let mut packet = ipv4_packet(ue_ip(), &[1, 2]);
        packet[0] = 0x60; // version 6
        let (mut buf, n) = downlink_buf(&packet);
        let table = table_with(TEID, sink());

        let action = handle_downlink(&table, &mut buf, n);

        assert!(
            matches!(action, DownlinkAction::Drop(DownlinkDropReason::NotIpv4)),
            "got {action:?}"
        );
    }

    #[test]
    fn downlink_drops_short_packet() {
        let (mut buf, n) = downlink_buf(&[0x45; 10]);
        let table = table_with(TEID, sink());

        let action = handle_downlink(&table, &mut buf, n);

        assert!(
            matches!(action, DownlinkAction::Drop(DownlinkDropReason::NotIpv4)),
            "got {action:?}"
        );
    }

    #[test]
    fn downlink_rejects_n_beyond_buffer() {
        let (mut buf, n) = downlink_buf(&ipv4_packet(ue_ip(), &[1, 2]));
        let table = table_with(TEID, sink());

        let action = handle_downlink(&table, &mut buf, n + 100);

        assert!(
            matches!(action, DownlinkAction::Drop(DownlinkDropReason::NotIpv4)),
            "got {action:?}"
        );
    }

    #[test]
    fn echo_request_gets_reply_to_sender() {
        let table = table_with(0, sink());

        let buf = echo_request(0x1234);
        let action = handle_uplink(&table, &buf, src());

        let UplinkAction::Reply { dst, datagram } = action else {
            panic!("expected Reply, got {action:?}");
        };
        assert_eq!(dst, src());
        assert_eq!(datagram, build_echo_response(0x1234));
    }

    #[test]
    fn echo_response_is_not_answered() {
        let table = table_with(TEID, sink());

        let buf = build_echo_response(5);
        let action = handle_uplink(&table, &buf, src());

        assert!(
            matches!(action, UplinkAction::Drop(UplinkDropReason::NotGpdu(_))),
            "got {action:?}"
        );
    }

    #[test]
    fn echo_request_without_sequence_is_malformed() {
        let buf = [0x30, 0x01, 0x00, 0x00, 0, 0, 0, 0];
        let table = table_with(TEID, sink());

        let action = handle_uplink(&table, &buf, src());

        assert!(
            matches!(action, UplinkAction::Drop(UplinkDropReason::Malformed(_))),
            "got {action:?}"
        );
    }
}
