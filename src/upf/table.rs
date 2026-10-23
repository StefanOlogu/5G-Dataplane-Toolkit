use crate::wire::BoxError;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};

#[derive(Clone, Copy, Debug)]
pub struct Session {
    pub ue_ip: Ipv4Addr,
    pub ul_teid: u32,
    pub dl_teid: u32,
    pub gnb: SocketAddr,
    pub n6_peer: SocketAddr,
    pub qfi:u8,
}

#[derive(Debug, Default)]
pub struct SessionTable {
    by_ul_teid: HashMap<u32, Session>,
    by_ue_ip: HashMap<Ipv4Addr, Session>,
}

impl SessionTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, session: Session) -> Result<(), BoxError> {
        if self.by_ue_ip.contains_key(&session.ue_ip) {
            return Err(format!("duplicate UE IP {}", session.ue_ip).into());
        }

        if self.by_ul_teid.contains_key(&session.ul_teid) {
            return Err(format!("duplicate uplink TEID {}", session.ul_teid).into());
        }

        self.by_ul_teid.insert(session.ul_teid, session);
        self.by_ue_ip.insert(session.ue_ip, session);

        Ok(())
    }

    pub fn lookup_uplink(&self, teid: u32) -> Option<Session> {
        self.by_ul_teid.get(&teid).copied()
    }

    pub fn lookup_downlink(&self, ue_ip: Ipv4Addr) -> Option<Session> {
        self.by_ue_ip.get(&ue_ip).copied()
    }
}
