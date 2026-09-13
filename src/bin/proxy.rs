use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main()-> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:6060").await?;

    loop{
        let (mut stream, addr) = listener.accept().await?;
        tokio::spawn(async move {
            let mut upstream = match TcpStream::connect("127.0.0.1:5050").await {
                Ok(s) => s,
                Err(e) => {
                    println!("upstream dial failed: {e}");
                    return;
                }
            };
            println!("client connected: {:?}", addr);

            let (mut client_read, mut client_write) = stream.split();
            let (mut upstream_read, mut upstream_write) = upstream.split();
            let client_upstream = tokio::io::copy(&mut client_read, &mut upstream_write);
            let upstream_client = tokio::io::copy(&mut upstream_read, &mut client_write);

            if let Err(e) = tokio::try_join!(client_upstream, upstream_client) {
                println!("client disconnected: {e}");
            }
        });
    }
}