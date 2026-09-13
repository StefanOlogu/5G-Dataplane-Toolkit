use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tracing::{info, error, warn};
use tokio::signal::ctrl_c;

#[tokio::main]
async fn main()-> std::io::Result<()> {
    tracing_subscriber::fmt::init();
    let listener = TcpListener::bind("127.0.0.1:6060").await?;
    info!("Proxy listening on 127.0.0.1:6060");

    loop{
        select! {
            result = listener.accept() => {
                let (mut stream, addr) = match result{
                    Ok(a) => a,
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                        continue;
                    }
                };
                tokio::spawn(async move {
                    let mut upstream = match TcpStream::connect("127.0.0.1:5050").await {
                        Ok(s) => s,
                        Err(e) => {
                            error!("Failed to dial upstream: {e}");
                            return;
                        }
                    };
                    info!("Client connected: {:?}", addr);

                    match tokio::io::copy_bidirectional(&mut stream, &mut upstream).await{
                        Ok((to_upstream,to_client)) => {
                            info!("Connection {:?} closed : {to_upstream:?} bytes up, {to_client:?} bytes down",addr);
                        }
                        Err(e)=>{
                            warn!("Connection {:?} error: {e}",addr);
                            return;
                        }
                    };

                    // let (mut client_read, mut client_write) = stream.split();
                    // let (mut upstream_read, mut upstream_write) = upstream.split();
                    // let client_upstream = tokio::io::copy(&mut client_read, &mut upstream_write);
                    // let upstream_client = tokio::io::copy(&mut upstream_read, &mut client_write);
                    //
                    // if let Err(e) = tokio::try_join!(client_upstream, upstream_client) {
                    //     warn!("Client or Proxy disconnected: {e}");
                    // }


                });
            }
            _ = ctrl_c() => {
                info!("Shutdown signal received");
                break;
            }
        }
    }
    Ok(())
}