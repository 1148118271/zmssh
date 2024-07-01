// pub(crate) use session_inner::SessionInner;
mod session_broker;
mod session_local;

pub use session_broker::SessionBroker;
pub use session_local::LocalSession;
use tracing::*;

use std::{
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    path::Path,
    time::Duration,
};

use crate::{
    algorithm::{Compress, Digest, Enc, Kex, Mac, PubKey},
    client::Client,
    config::{algorithm::AlgList, Config},
    error::SshResult,
    model::{Packet, SecPacket},
};

enum SessionState<S>
where
    S: Read + Write,
{
    Init(Config, S),
    Version(Config, S),
    Auth(Client, S),
    Connected(Client, S),
}

pub struct SessionConnector<S>
where
    S: Read + Write,
{
    inner: SessionState<S>,
}

impl<S> SessionConnector<S>
where
    S: Read + Write,
{
    fn connect(self) -> SshResult<Self> {
        match self.inner {
            SessionState::Init(config, stream) => Self {
                inner: SessionState::Version(config, stream),
            }
            .connect(),
            SessionState::Version(mut config, mut stream) => {
                info!("start for version negotiation.");
                // Send Client version
                config.ver.send_our_version(&mut stream)?;

                // Receive the server version
                config
                    .ver
                    .read_server_version(&mut stream, config.timeout)?;
                // Version validate
                config.ver.validate()?;

                // from now on
                // each step of the interaction is subject to the ssh constraints on the packet
                // so we create a client to hide the underlay details
                let client = Client::new(config);

                Self {
                    inner: SessionState::Auth(client, stream),
                }
                .connect()
            }
            SessionState::Auth(mut client, mut stream) => {
                // before auth,
                // we should have a key exchange at first
                let mut digest = Digest::new();
                let server_algs = SecPacket::from_stream(&mut stream, &mut client)?;
                digest.hash_ctx.set_i_s(server_algs.get_inner());
                let server_algs = AlgList::unpack(server_algs)?;
                client.key_agreement(&mut stream, server_algs, &mut digest)?;
                client.do_auth(&mut stream, &digest)?;
                Ok(Self {
                    inner: SessionState::Connected(client, stream),
                })
            }
            _ => unreachable!(),
        }
    }

    /// To run this ssh session on the local thread
    ///
    /// It will return a [LocalSession] which doesn't support multithread concurrency
    ///
    pub fn run_local(self) -> LocalSession<S> {
        if let SessionState::Connected(client, stream) = self.inner {
            LocalSession::new(client, stream)
        } else {
            unreachable!("Why you here?")
        }
    }

    /// close the session and consume it
    ///
    pub fn close(self) {
        drop(self)
    }
}

impl<S> SessionConnector<S>
where
    S: Read + Write + Send + 'static,
{
    /// To spwan a new thread to run this ssh session
    ///
    /// It will return a [SessionBroker] which supports multithread concurrency
    ///
    pub fn run_backend(self) -> SessionBroker {
        if let SessionState::Connected(client, stream) = self.inner {
            SessionBroker::new(client, stream)
        } else {
            unreachable!("Why you here?")
        }
    }
}

#[derive(Default)]
pub struct SessionBuilder {
    config: Config,
}

impl SessionBuilder {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    pub fn disable_default() -> Self {
        Self {
            config: Config::disable_default(),
        }
    }

    /// Read/Write timeout for local SSH mode. Use None to disable timeout.
    /// This is a global timeout only take effect after the session is established
    ///
    /// Use `connect_with_timeout` instead if you want to add timeout
    /// when connect to the target SSH server
    pub fn timeout(mut self, timeout: Option<Duration>) -> Self {
        self.config.timeout = timeout;
        self
    }

    pub fn username(mut self, username: &str) -> Self {
        self.config.auth.username(username).unwrap();
        self
    }

    pub fn password(mut self, password: &str) -> Self {
        self.config.auth.password(password).unwrap();
        self
    }

    pub fn private_key<K>(mut self, private_key: K) -> Self
    where
        K: ToString,
    {
        match self.config.auth.private_key(private_key) {
            Ok(_) => (),
            Err(e) => error!(
                "Parse private key from string: {}, will fallback to password authentication",
                e
            ),
        }
        self
    }

    pub fn private_key_path<P>(mut self, key_path: P) -> Self
    where
        P: AsRef<Path>,
    {
        match self.config.auth.private_key_path(key_path) {
            Ok(_) => (),
            Err(e) => error!(
                "Parse private key from file: {}, will fallback to password authentication",
                e
            ),
        }
        self
    }

    pub fn add_kex_algorithms(mut self, alg: Kex) -> Self {
        self.config.algs.key_exchange.push(alg);
        self
    }

    pub fn del_kex_algorithms(mut self, alg: Kex) -> Self {
        self.config.algs.key_exchange.retain(|x| *x != alg);
        self
    }

    pub fn add_pubkey_algorithms(mut self, alg: PubKey) -> Self {
        self.config.algs.public_key.push(alg);
        self
    }

    pub fn del_pubkey_algorithms(mut self, alg: PubKey) -> Self {
        self.config.algs.public_key.retain(|x| *x != alg);
        self
    }

    pub fn add_enc_algorithms(mut self, alg: Enc) -> Self {
        self.config.algs.c_encryption.push(alg);
        self.config.algs.s_encryption.push(alg);
        self
    }

    pub fn del_enc_algorithms(mut self, alg: Enc) -> Self {
        self.config.algs.c_encryption.retain(|x| *x != alg);
        self.config.algs.s_encryption.retain(|x| *x != alg);
        self
    }

    pub fn add_mac_algortihms(mut self, alg: Mac) -> Self {
        self.config.algs.c_mac.push(alg);
        self.config.algs.s_mac.push(alg);
        self
    }

    pub fn del_mac_algortihms(mut self, alg: Mac) -> Self {
        self.config.algs.c_mac.retain(|x| *x != alg);
        self.config.algs.s_mac.retain(|x| *x != alg);
        self
    }

    pub fn add_compress_algorithms(mut self, alg: Compress) -> Self {
        self.config.algs.c_compress.push(alg);
        self.config.algs.s_compress.push(alg);
        self
    }

    pub fn del_compress_algorithms(mut self, alg: Compress) -> Self {
        self.config.algs.c_compress.retain(|x| *x != alg);
        self.config.algs.s_compress.retain(|x| *x != alg);
        self
    }

    /// Create a TCP connection to the target server
    ///
    pub fn connect<A>(self, addr: A) -> SshResult<SessionConnector<TcpStream>>
    where
        A: ToSocketAddrs,
    {
        // connect tcp by default
        let tcp = if let Some(ref to) = self.config.timeout {
            TcpStream::connect_timeout(&addr.to_socket_addrs()?.next().unwrap(), *to)?
        } else {
            TcpStream::connect(addr)?
        };

        // default nonblocking
        tcp.set_nonblocking(true).unwrap();
        self.connect_bio(tcp)
    }

    /// Create a TCP connection to the target server, with timeout provided
    ///
    pub fn connect_with_timeout<A>(
        self,
        addr: A,
        timeout: Option<Duration>,
    ) -> SshResult<SessionConnector<TcpStream>>
    where
        A: ToSocketAddrs,
    {
        // connect tcp with custom connection timeout
        let tcp = if let Some(ref to) = timeout {
            TcpStream::connect_timeout(&addr.to_socket_addrs()?.next().unwrap(), *to)?
        } else {
            TcpStream::connect(addr)?
        };

        // default nonblocking
        tcp.set_nonblocking(true).unwrap();
        self.connect_bio(tcp)
    }

    /// connect to target server w/ a bio object
    ///
    /// which requires to implement `std::io::{Read, Write}`
    ///
    pub fn connect_bio<S>(mut self, stream: S) -> SshResult<SessionConnector<S>>
    where
        S: Read + Write,
    {
        self.config.tune_alglist_on_private_key();
        SessionConnector {
            inner: SessionState::Init(self.config, stream),
        }
        .connect()
    }
}
