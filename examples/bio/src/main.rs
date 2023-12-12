
use std::net::{TcpStream, ToSocketAddrs};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

fn main() {
    // a builder for `FmtSubscriber`.
    let subscriber = FmtSubscriber::builder()
        // all spans/events with a level higher than INFO (e.g, info, warn, etc.)
        // will be written to stdout.
        .with_max_level(Level::INFO)
        // completes the builder.
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let bio = MyProxy::new("127.0.0.1:22");

    let mut session = ssh::create_session()
        .username("ubuntu")
        .password("password")
        .private_key_path("./id_rsa")
        .connect_bio(bio)
        .unwrap()
        .run_local();
    let exec = session.open_exec().unwrap();
    let vec: Vec<u8> = exec.send_command("ls -all").unwrap();
    println!("{}", String::from_utf8(vec).unwrap());
    // Close session.
    session.close();
}

// Use a real ssh server since I don't wanna implement a ssh-server in the example codes
struct MyProxy {
    server: TcpStream,
}

impl MyProxy {
    fn new<A>(addr: A) -> Self
    where
        A: ToSocketAddrs,
    {
        Self {
            server: TcpStream::connect(addr).unwrap(),
        }
    }
}

impl std::io::Read for MyProxy {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        println!("bio log: read {} bytes", buf.len());
        self.server.read(buf)
    }
}

impl std::io::Write for MyProxy {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        println!("bio log: write {} bytes", buf.len());
        self.server.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.server.flush()
    }
}
