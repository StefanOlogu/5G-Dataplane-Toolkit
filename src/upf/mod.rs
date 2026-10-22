use crate::upf::decision::{UplinkAction, handle_uplink};
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
        let mut buf = vec![0u8; 65536];
        loop {
            let (n, src) = match self.n3.recv_from(&mut buf).await {
                Ok((n, src)) => (n, src),
                Err(e) => {
                    eprintln!("n3 recv error: {}", e);
                    continue;
                }
            };

            let action = handle_uplink(&self.table, &buf[..n], src);
            match action {
                UplinkAction::Forward { dst, payload } => {
                    if let Err(e) = self.n6.send_to(payload, dst).await {
                        eprintln!("n6 send to {dst} failed: {}", e);
                    }
                }

                UplinkAction::Drop(reason) => eprintln!("drop from {src}: {reason:?}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gtp::fixtures::gpdu;
    use std::net::SocketAddr;
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
}
