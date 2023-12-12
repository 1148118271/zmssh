#[cfg(unix)]
use mio::unix::SourceFd;

use std::fs::File;
#[cfg(unix)]
use std::os::unix::io::FromRawFd;
use std::time::Duration;
use std::{cell::RefCell, rc::Rc};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

use mio::net::TcpStream;
use mio::{event::Source, Events, Interest, Poll, Token};

const SERVER: Token = Token(0);
const SHELL: Token = Token(1);

#[cfg(not(unix))]
fn main() {
    panic!("This example can run on unix only")
}

#[cfg(unix)]
fn main() {
    use std::{io::Read, os::unix::prelude::AsRawFd};

    // a builder for `FmtSubscriber`.
    let subscriber = FmtSubscriber::builder()
        // all spans/events with a level higher than INFO (e.g, info, warn, etc.)
        // will be written to stdout.
        .with_max_level(Level::INFO)
        // completes the builder.
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
    let tcp = TcpStream::connect("127.0.0.1:22".parse().unwrap()).unwrap();
    let mut session = ssh::create_session()
        .username("ubuntu")
        .password("password")
        .timeout(Some(Duration::from_millis(1000)))
        .private_key_path("./id_rsa")
        .connect_bio(tcp)
        .unwrap()
        .run_local();

    let mut shell = session.open_shell().unwrap();
    let mut tcp_wrap = TcpWrap::new(session.get_raw_io());
    let mut std_in = unsafe { File::from_raw_fd(0) };

    let mut poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(1024);
    poll.registry()
        .register(&mut tcp_wrap, SERVER, Interest::READABLE)
        .unwrap();
    poll.registry()
        .register(
            &mut SourceFd(&std_in.as_raw_fd()),
            SHELL,
            Interest::READABLE,
        )
        .unwrap();

    let mut buf = [0; 2048];

    'main_loop: loop {
        poll.poll(&mut events, None).unwrap();

        for event in &events {
            match event.token() {
                SERVER => match shell.read() {
                    Ok(buf) => print!("{}", String::from_utf8_lossy(&buf)),
                    _ => break 'main_loop,
                },
                SHELL => {
                    let len = std_in.read(&mut buf).unwrap();
                    shell.write(&buf[..len]).unwrap();
                }
                _ => break 'main_loop,
            }
        }
    }
    session.close();
}
struct TcpWrap {
    server: Rc<RefCell<TcpStream>>,
}

impl TcpWrap {
    fn new(tcp: Rc<RefCell<TcpStream>>) -> Self {
        Self { server: tcp }
    }
}

impl std::io::Read for TcpWrap {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        println!("bio log: read {} bytes", buf.len());
        self.server.borrow_mut().read(buf)
    }
}

impl std::io::Write for TcpWrap {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        println!("bio log: write {} bytes", buf.len());
        self.server.borrow_mut().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.server.borrow_mut().flush()
    }
}

impl Source for TcpWrap {
    fn deregister(&mut self, registry: &mio::Registry) -> std::io::Result<()> {
        self.server.borrow_mut().deregister(registry)
    }
    fn register(
        &mut self,
        registry: &mio::Registry,
        token: Token,
        interests: Interest,
    ) -> std::io::Result<()> {
        self.server
            .borrow_mut()
            .register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &mio::Registry,
        token: Token,
        interests: Interest,
    ) -> std::io::Result<()> {
        self.server
            .borrow_mut()
            .reregister(registry, token, interests)
    }
}
