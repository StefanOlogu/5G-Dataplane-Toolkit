use tokio::net::UdpSocket;
use dataplane::wire::BoxError;
use dataplane::upf::{Upf,ForwardingTable};

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let n3 = UdpSocket::bind("0.0.0.0:2152").await?;
    let n6 = UdpSocket::bind("0.0.0.0:0").await?;
    let mut table = ForwardingTable::new();

    table.insert(1,"127.0.0.1:9000".parse()?);

    eprintln!("UPF up: N3 on {}, N6 on {}", n3.local_addr()?, n6.local_addr()?);
    eprintln!("  TEID 1 -> 127.0.0.1:9000");

    Upf::new(n3, n6, table).run().await?;
    Ok(())
}