use sha1::{Digest, Sha1};
use std::error::Error;
use std::env;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task;
use tokio::time;


pub struct Tob {
    stream: TcpStream
}

impl Tob {
    async fn connect(addr: &SocketAddr) -> Result<Self, Box<dyn Error>> {
	Ok(Self {
	    stream: TcpStream::connect(addr).await?
	})
    }

    pub async fn broadcast(&mut self, msg: &[u8]) {
	let magic: u32 = 0;
	let opcode: u8 = 100;
	let length: u32 = msg.len().try_into().unwrap();
	let mut hasher = Sha1::new();

	hasher.update(msg);

	let hash = hasher.finalize();

	self.stream.write(&magic.to_le_bytes()).await;
	self.stream.write(&opcode.to_le_bytes()).await;
	self.stream.write(&length.to_le_bytes()).await;
	self.stream.write(&hash[0..4]).await;
	self.stream.write(msg).await;
    }

    pub async fn deliver(&mut self) -> Vec<u8> {
	let mut buf = vec![0; 13];

	self.stream.read_exact(&mut buf).await;

	let length = u32::from_le_bytes(buf[5..9].try_into().unwrap());
	let mut msg = vec![0; length.try_into().unwrap()];

	self.stream.read_exact(&mut msg).await;

	return msg;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    let clid: u64 = args[0].parse::<u64>().expect("invalid client id");
    let tickms: u64 = args[1].parse::<u64>().expect("invalid tick ms");
    let burst: u64 = args[2].parse::<u64>().expect("invalid burst");
    let msglen: usize = args[3].parse::<usize>().expect("invalid msg length");
    let addr: SocketAddr = args[4].parse().expect("invalid address");

    task::spawn(async move {
	let mut ticker = time::interval(Duration::from_millis(tickms));
	let mut tob: Tob = Tob::connect(&addr).await.unwrap();
	let mut msg = vec![0u8; msglen];
	let mut msgid: u64 = 0;

	loop {
	    tokio::select! {
		_ = ticker.tick() => {
		    for _ in 0 .. burst {
			msg[0..8].copy_from_slice(&clid.to_be_bytes());
			msg[8..16].copy_from_slice(&msgid.to_be_bytes());
			msgid += 1;
			tob.broadcast(&msg).await;
		    }
		}
		rep = tob.deliver() => {
		    let sender =
			u64::from_be_bytes(rep[0..8].try_into().unwrap());
		    let msgid =
			u64::from_be_bytes(rep[8..16].try_into().unwrap());
		    println!("deliver {}:{}", sender, msgid)
		}
	    }
	}
    }).await;

    Ok(())
}
