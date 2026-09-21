use std::net::UdpSocket;
use tracing::{error, info};
use dataplane::dns::{build_query, parse_message};

fn main(){
    tracing_subscriber::fmt::init();

    let listener = UdpSocket::bind("0.0.0.0:0").unwrap();
    info!("Listening on {:?}", listener.local_addr());

    let query = match build_query("example.com",1){
        Ok(q) => q,

        Err(e) =>{
            error!("Failed to build query: {e}");
            return;
        }
    };

    listener.send_to(&query,"1.1.1.1:53").unwrap();

    let mut response = [0u8; 512];

    let(len,_src) = listener.recv_from(&mut response).unwrap();
    let msg = parse_message(&response[..len]).unwrap();

    for ans in msg.answers(){
        if ans.record_type() == 1 && ans.rdata().len() == 4{
            let ip = ans.rdata();
            println!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
        }
    }

}