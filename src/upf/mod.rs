use crate::upf::table::ForwardingTable;
use tokio::net::UdpSocket;

mod decision;
mod table;

pub struct Upf {
    n3: UdpSocket,
    n6: UdpSocket,
    table: ForwardingTable,
}
