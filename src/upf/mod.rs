use std::net::SocketAddr;
use crate::upf::decision::{handle_uplink, UplinkAction, HEADROOM, handle_downlink, DownlinkAction};
use tokio::net::UdpSocket;

mod decision;
mod table;

pub use crate::upf::table::{Session, SessionTable};

pub struct Upf {
    n3: UdpSocket,
    n6: UdpSocket,
    table: SessionTable,
}

impl Upf {
    pub fn new(n3: UdpSocket, n6: UdpSocket, table: SessionTable) -> Self {
        Self { n3, n6, table }
    }

    pub async fn run(self) -> std::io::Result<()> {
        let mut ul_buf = vec![0u8; 65536];
        let mut dl_buf = vec![0u8; HEADROOM + 65536];
        loop {
            tokio::select! {
                res = self.n3.recv_from(&mut ul_buf) => match res {
                    Ok((n, src)) => self.uplink(&ul_buf[..n], src).await,
                    Err(e) => eprintln!("n3 recv error: {e}"),
                },
                res = self.n6.recv_from(&mut dl_buf[HEADROOM..]) => match res {
                    Ok((n, src)) => self.downlink(&mut dl_buf, n, src).await,
                    Err(e) => eprintln!("n6 recv error: {e}"),
                },
            }
        }
    }

    async fn uplink(&self, packet: &[u8], src: SocketAddr) {
        let action = handle_uplink(&self.table, packet, src);
        match action {
            UplinkAction::Forward { dst, payload } => {
                if let Err(e) = self.n6.send_to(payload, dst).await {
                    eprintln!("n6 send to {dst} failed: {e}");
                }
            }
            UplinkAction::Drop(reason) => eprintln!("Uplink dropped from {src}: {reason:?}"),
        }
    }

    async fn downlink(&self, buf: &mut [u8],n: usize, src: SocketAddr) {
        let action = handle_downlink(&self.table, buf,n);
        match action {
            DownlinkAction::Forward { dst, datagram } => {
                if let Err(e) = self.n3.send_to(datagram, dst).await {
                    eprintln!("n3 send to {dst} failed: {e}");
                }
            }
            DownlinkAction::Drop(reason) => eprintln!("Downlink dropped from {src}: {reason:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gtp::fixtures::gpdu;
    use std::time::Duration;
    use tokio::task::JoinHandle;
    use tokio::time::timeout;
    use crate::gtp::{dispatch_gtpu, parse_gtpu_header};

    const TEID: u32 = 0x1234_5678;

    struct Harness {
        gnb: UdpSocket,
        sink: UdpSocket,
        n3_addr: SocketAddr,
        n6_addr: SocketAddr,
        handle: JoinHandle<std::io::Result<()>>,
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
            })
            .unwrap();

        let handle = tokio::spawn(Upf::new(n3, n6, table).run());
        Harness {
            gnb,
            sink,
            n3_addr,
            n6_addr,
            handle,
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
}
