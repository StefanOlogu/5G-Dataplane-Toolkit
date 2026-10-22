use dataplane::upf::{Session, SessionTable, Upf};
use dataplane::wire::BoxError;
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let n3 = UdpSocket::bind("0.0.0.0:2152").await?;
    let n6 = UdpSocket::bind("0.0.0.0:0").await?;
    let mut table = SessionTable::new();
    let session = Session {
        ue_ip: "10.45.0.2".parse()?,
        ul_teid: 1,
        dl_teid: 0x0000_0001,
        gnb: "127.0.0.1:2153".parse()?,
        n6_peer: "127.0.0.1:9000".parse()?,
    };

    table.insert(session)?;

    eprintln!(
        "UPF up: N3 on {}, N6 on {}",
        n3.local_addr()?,
        n6.local_addr()?
    );
    eprintln!("  session: {session:?}");

    Upf::new(n3, n6, table).run().await?;
    Ok(())
}
