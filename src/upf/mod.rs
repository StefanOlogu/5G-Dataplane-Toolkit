use crate::upf::decision::{handle_downlink, handle_uplink, DownlinkAction, UplinkAction, UplinkDropReason, HEADROOM, DownlinkDropReason};
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use std::sync::Arc;
use crate::upf::counters::inc;
pub use crate::upf::counters::{CounterSnapshot, Counters};

mod decision;
mod table;
mod counters;

pub use crate::upf::table::{Session, SessionTable};

#[derive(Clone)]
pub struct Upf {
    n3: Arc<UdpSocket>,
    n6: Arc<UdpSocket>,
    table: Arc<SessionTable>,
    counters: Arc<Counters>,
}

impl Upf {

    pub fn new(n3: UdpSocket, n6: UdpSocket, table: SessionTable) -> Self {
        Self {
            n3: Arc::new(n3),
            n6: Arc::new(n6),
            table: Arc::new(table),
            counters: Arc::new(Counters::default()),
        }
    }

    pub fn counters(&self) -> Arc<Counters> {
        Arc::clone(&self.counters)
    }
    pub async fn run(self) -> std::io::Result<()> {
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(self.clone().report_loop());
        tasks.spawn(self.clone().uplink_loop());
        tasks.spawn(self.downlink_loop());

        match tasks.join_next().await {
            Some(Ok(result)) => result,
            Some(Err(join_err)) => Err(std::io::Error::other(join_err)),
            None => Ok(()),
        }
    }

    async fn uplink(&self, packet: &[u8], src: SocketAddr) {
        let c = &self.counters;
        match handle_uplink(&self.table, packet, src) {
            UplinkAction::Forward { dst, payload } => {
                inc(&c.ul_forwarded);
                if let Err(e) = self.n6.send_to(payload, dst).await {
                    inc(&c.send_errors);
                    eprintln!("n6 send to {dst} failed: {e}");
                }
            }
            UplinkAction::Reply { dst, datagram } => {
                inc(&c.ul_echo_replies);
                if let Err(e) = self.n3.send_to(&datagram, dst).await {
                    inc(&c.send_errors);
                    eprintln!("n3 echo reply to {dst} failed: {e}");
                }
            }
            UplinkAction::Drop(reason) => match reason {
                UplinkDropReason::Malformed(_) => inc(&c.ul_malformed),
                UplinkDropReason::NotGpdu(_) => inc(&c.ul_not_gpdu),
                UplinkDropReason::UnknownTeid(_) => inc(&c.ul_unknown_teid),
            },
        }
    }

    async fn uplink_loop(self) -> std::io::Result<()> {
        let mut buf = vec![0u8; 65536];
        loop {
            match self.n3.recv_from(&mut buf).await {
                Ok((n, src)) => self.uplink(&buf[..n], src).await,
                Err(e) => {
                    eprintln!("n3 recv error: {e}");
                    inc(&self.counters.recv_errors);
                },
            }
        }
    }

    async fn downlink(&self, buf: &mut [u8], n: usize, _src: SocketAddr) {
        let c = &self.counters;
        match handle_downlink(&self.table, buf, n) {
            DownlinkAction::Forward { dst, datagram } => {
                inc(&c.dl_forwarded);
                if let Err(e) = self.n3.send_to(datagram, dst).await {
                    inc(&c.send_errors);
                    eprintln!("n3 send to {dst} failed: {e}");
                }
            }
            DownlinkAction::Drop(reason) => match reason {
                DownlinkDropReason::NotIpv4 => inc(&c.dl_not_ipv4),
                DownlinkDropReason::UnknownUe(_) => inc(&c.dl_unknown_ue),
                DownlinkDropReason::Encap(_) => inc(&c.dl_encap_error),
            },
        }
    }

    async fn downlink_loop(self) -> std::io::Result<()> {
        let mut buf = vec![0u8; HEADROOM + 65536];
        loop {
            match self.n6.recv_from(&mut buf[HEADROOM..]).await {
                Ok((n, src)) => self.downlink(&mut buf,n, src).await,
                Err(e) => {
                    eprintln!("n6 recv error: {e}");
                    inc(&self.counters.recv_errors);
                }
            }
        }
    }

    async fn report_loop(self) -> std::io::Result<()> {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(10));
        let mut last = CounterSnapshot::default();
        loop {
            tick.tick().await;
            let now = self.counters.snapshot();
            if now != last {
                eprintln!("{now:#?}");
                last = now;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gtp::fixtures::{echo_request, gpdu};
    use crate::gtp::{build_echo_response, dispatch_gtpu, parse_gtpu_header};
    use std::time::Duration;
    use tokio::task::JoinHandle;
    use tokio::time::timeout;

    const TEID: u32 = 0x1234_5678;

    struct Harness {
        gnb: UdpSocket,
        sink: UdpSocket,
        n3_addr: SocketAddr,
        n6_addr: SocketAddr,
        handle: JoinHandle<std::io::Result<()>>,
        counters: Arc<Counters>,
    }

    async fn start_upf() -> Harness {
        let n3 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let n6 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let gnb = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let n3_addr = n3.local_addr().unwrap();
        let n6_addr = n6.local_addr().unwrap();

        let mut table = SessionTable::new();
        table
            .insert(Session {
                ue_ip: "10.45.0.2".parse().unwrap(),
                ul_teid: TEID,
                dl_teid: 0x0000_0001,
                gnb: gnb.local_addr().unwrap(),
                n6_peer: sink.local_addr().unwrap(),
                qfi: 9,
            })
            .unwrap();

        let upf = Upf::new(n3, n6, table);
        let counters = upf.counters();
        let handle = tokio::spawn(upf.run());

        Harness {
            gnb,
            sink,
            n3_addr,
            n6_addr,
            handle,
            counters
        }
    }

    async fn recv_one(sock: &UdpSocket) -> (Vec<u8>, SocketAddr) {
        let mut buf = [0u8; 2048];
        let (n, from) = timeout(Duration::from_secs(1), sock.recv_from(&mut buf))
            .await
            .expect("timed out waiting for a forwarded packet")
            .expect("recv failed");
        (buf[..n].to_vec(), from)
    }

    #[tokio::test]
    async fn forwards_decapsulated_payload_via_n6() {
        let h = start_upf().await;

        h.gnb
            .send_to(&gpdu(TEID, &[1, 2, 3, 4]), h.n3_addr)
            .await
            .unwrap();

        let (data, from) = recv_one(&h.sink).await;
        assert_eq!(data, [1, 2, 3, 4]);
        assert_eq!(from, h.n6_addr);
        h.handle.abort();
    }

    #[tokio::test]
    async fn survives_garbage_then_keeps_forwarding() {
        let h = start_upf().await;

        let echo = [0x32, 0x01, 0x00, 0x04, 0, 0, 0, 0, 0x00, 0x01, 0x00, 0x00];
        let poison: [&[u8]; 4] = [&[0xFF, 0x00], &[], &gpdu(0xDEAD_BEEF, &[7, 7]), &echo];
        for p in poison {
            h.gnb.send_to(p, h.n3_addr).await.unwrap();
        }

        h.gnb
            .send_to(&gpdu(TEID, &[9, 9, 9, 9]), h.n3_addr)
            .await
            .unwrap();

        let (data, _) = recv_one(&h.sink).await;
        assert_eq!(data, [9, 9, 9, 9]);
        assert!(!h.handle.is_finished(), "UPF loop exited");

        assert_eq!(
            h.counters.snapshot(),
            CounterSnapshot {
                ul_malformed: 2,
                ul_unknown_teid: 1,
                ul_echo_replies: 1,
                ul_forwarded: 1,
                ..Default::default()
            }
        );
        h.handle.abort();
    }

    fn ipv4_packet(dst: &str, payload: &[u8]) -> Vec<u8> {
        let dst: std::net::Ipv4Addr = dst.parse().unwrap();
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[16..20].copy_from_slice(&dst.octets());
        p.extend_from_slice(payload);
        p
    }

    #[tokio::test]
    async fn encapsulates_downlink_and_sends_via_n3() {
        let h = start_upf().await;

        let packet = ipv4_packet("10.45.0.2", &[5, 6, 7, 8]);
        h.sink.send_to(&packet, h.n6_addr).await.unwrap();

        let (data, from) = recv_one(&h.gnb).await;
        assert_eq!(from, h.n3_addr);

        let (header, _) = parse_gtpu_header(&data).unwrap();
        assert_eq!(header.teid(), 0x0000_0001);
        assert_eq!(dispatch_gtpu(&header, &data).unwrap(), Some(&packet[..]));
        h.handle.abort();
    }
    #[tokio::test]
    async fn downlink_counts_drops_and_forwards() {
        let h = start_upf().await;

        let mut ipv6 = ipv4_packet("10.45.0.2", &[1]);
        ipv6[0] = 0x60;
        h.sink.send_to(&ipv6, h.n6_addr).await.unwrap();
        h.sink.send_to(&ipv4_packet("10.45.0.3", &[1]), h.n6_addr).await.unwrap(); // no session
        h.sink.send_to(&ipv4_packet("10.45.0.2", &[1]), h.n6_addr).await.unwrap(); // probe

        recv_one(&h.gnb).await;

        assert_eq!(
            h.counters.snapshot(),
            CounterSnapshot {
                dl_not_ipv4: 1,
                dl_unknown_ue: 1,
                dl_forwarded: 1,
                ..Default::default()
            }
        );
        h.handle.abort();
    }

    #[tokio::test]
    async fn answers_echo_request_on_n3() {
        let h = start_upf().await;

        h.gnb.send_to(&echo_request(0x4242), h.n3_addr).await.unwrap();

        let (data, from) = recv_one(&h.gnb).await;
        assert_eq!(from, h.n3_addr);
        assert_eq!(data, build_echo_response(0x4242));
        assert_eq!(h.counters.snapshot().ul_echo_replies, 1);
        h.handle.abort();
    }

}
