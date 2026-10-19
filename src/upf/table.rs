use std::collections::HashMap;
use std::net::SocketAddr;

#[derive(Default, Debug)]
pub struct ForwardingTable(HashMap<u32, SocketAddr>);

impl ForwardingTable {
    pub fn new() -> Self {
        ForwardingTable(HashMap::new())
    }

    pub fn insert(&mut self, teid: u32, addr: SocketAddr) -> Option<SocketAddr> {
        self.0.insert(teid, addr)
    }

    pub fn lookup(&self, teid: u32) -> Option<SocketAddr> {
        self.0.get(&teid).copied()
    }
}
