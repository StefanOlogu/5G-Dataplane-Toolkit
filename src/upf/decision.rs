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
