use crate::gtp::{MessageType, dispatch_gtpu, parse_gtpu_header};
use crate::upf::table::ForwardingTable;
use crate::wire::BoxError;
use std::net::SocketAddr;

#[derive(Debug)]
pub enum Action<'a> {
    Forward { dst: SocketAddr, payload: &'a [u8] },
    Drop(DropReason),
    //TODO:Echo -> Reply
}

#[derive(Debug)]
pub enum DropReason {
    Malformed(BoxError),
    NotGpdu(MessageType),
    UnknownTeid(u32),
}

pub fn handle_datagram<'a>(table: &ForwardingTable, buf: &'a [u8], _src: SocketAddr) -> Action<'a> {
    let (header, _) = match parse_gtpu_header(buf) {
        Ok(header) => header,

        Err(e) => return Action::Drop(DropReason::Malformed(e)),
    };

    let tpdu = match dispatch_gtpu(&header, buf) {
        Ok(Some(tpdu)) => tpdu,
        Ok(None) => return Action::Drop(DropReason::NotGpdu(header.message_type())),
        Err(e) => return Action::Drop(DropReason::Malformed(e)),
    };

    let Some(dst) = table.lookup(header.teid()) else {
        return Action::Drop(DropReason::UnknownTeid(header.teid()));
    };

    Action::Forward { dst, payload: tpdu }
}

#[cfg(test)]
mod tests {
    use crate::gtp::fixtures::gpdu;
    use super::*;

    const TEID: u32 = 0x1234_5678;

    fn src() -> SocketAddr {
        "10.0.0.1:2152".parse().unwrap()
    }

    fn sink() -> SocketAddr {
        "127.0.0.1:9000".parse().unwrap()
    }

    fn table_with(teid: u32, dst: SocketAddr) -> ForwardingTable {
        let mut t = ForwardingTable::new();
        t.insert(teid, dst);
        t
    }

    #[test]
    fn forwards_gpdu_with_known_teid() {
        let buf = gpdu(TEID, &[1, 2, 3, 4]);
        let table = table_with(TEID, sink());

        let action = handle_datagram(&table, &buf, src());

        let Action::Forward { dst, payload } = action else {
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

        let action = handle_datagram(&table, &buf, src());

        let Action::Forward { payload, .. } = action else {
            panic!("expected Forward, got {action:?}");
        };
        assert_eq!(payload, &[0xAAu8, 0xBB, 0xCC, 0xDD][..]);
    }

    #[test]
    fn drops_unknown_teid() {
        let buf = gpdu(TEID, &[1, 2, 3, 4]);
        let table = table_with(0xDEAD_BEEF, sink());

        let action = handle_datagram(&table, &buf, src());

        assert!(
            matches!(action, Action::Drop(DropReason::UnknownTeid(t)) if t == TEID),
            "got {action:?}"
        );
    }

    #[test]
    fn echo_request_not_forwarded_even_if_teid_zero_is_mapped() {
        let buf = [0x32, 0x01, 0x00, 0x04, 0, 0, 0, 0, 0x00, 0x01, 0x00, 0x00];
        let table = table_with(0, sink());

        let action = handle_datagram(&table, &buf, src());

        assert!(
            matches!(action, Action::Drop(DropReason::NotGpdu(_))),
            "got {action:?}"
        );
    }

    #[test]
    fn drops_when_length_field_exceeds_buffer() {
        let mut buf = gpdu(TEID, &[1, 2, 3, 4]);
        buf.truncate(buf.len() - 2);
        let table = table_with(TEID, sink());

        let action = handle_datagram(&table, &buf, src());

        assert!(
            matches!(action, Action::Drop(DropReason::Malformed(_))),
            "got {action:?}"
        );
    }

    #[test]
    fn drops_truncated_header() {
        let buf = gpdu(TEID, &[1, 2, 3, 4]);
        let table = table_with(TEID, sink());

        let action = handle_datagram(&table, &buf[..5], src());

        assert!(
            matches!(action, Action::Drop(DropReason::Malformed(_))),
            "got {action:?}"
        );
    }

    #[test]
    fn drops_empty_buffer() {
        let table = table_with(TEID, sink());

        let action = handle_datagram(&table, &[], src());

        assert!(
            matches!(action, Action::Drop(DropReason::Malformed(_))),
            "got {action:?}"
        );
    }

    #[test]
    fn zero_length_tpdu_behavior() {
        let buf = gpdu(TEID, &[]);
        let table = table_with(TEID, sink());

        let action = handle_datagram(&table, &buf, src());

        let Action::Forward { payload, .. } = action else {
            panic!("expected Forward with empty payload, got {action:?}");
        };
        assert!(payload.is_empty());
    }
}