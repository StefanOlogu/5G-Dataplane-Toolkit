use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
#[tokio::main]
async fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:5050").await?;
    loop {
        let (mut socket, addr) = listener.accept().await?;
        tokio::spawn(async move {
            println!("Accepted connection from {:?}", addr);
            loop {
                let mut buf = [0u8; 1024];
                let n = match socket.read(&mut buf).await {
                    Ok(n) => n,

                    Err(e) => {
                        println!("failed to read from socket; err = {:?}", e);
                        break;
                    }
                };

                if n == 0 {
                    break;
                } else {
                    match socket.write_all(&buf[..n]).await {
                        Ok(_) => {}
                        Err(e) => {
                            println!("failed to write to socket; err = {:?}", e);
                            break;
                        }
                    }
                }
            }
        });
    }
}
