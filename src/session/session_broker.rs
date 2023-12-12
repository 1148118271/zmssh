use std::{
    collections::HashMap,
    io::{Read, Write},
    sync::{
        mpsc::{self, Receiver, Sender, TryRecvError},
        Arc, Mutex,
    },
    thread::spawn,
};

use tracing::*;

use crate::{
    algorithm::Digest,
    channel::{BackendChannel, ExecBroker},
    client::Client,
    config::algorithm::AlgList,
    constant::{size, ssh_channel_fail_code, ssh_connection_code, ssh_str, ssh_transport_code},
    error::{SshError, SshResult},
    model::{ArcMut, BackendResp, BackendRqst, Data, Packet, SecPacket, U32Iter},
    ChannelBroker, ShellBrocker, TerminalSize,
};

#[cfg(feature = "scp")]
use crate::ScpBroker;

pub struct SessionBroker {
    channel_num: ArcMut<U32Iter>,
    snd: Sender<BackendRqst>,
}

impl SessionBroker {
    pub(crate) fn new<S>(client: Client, stream: S) -> Self
    where
        S: Read + Write + Send + 'static,
    {
        let (rqst_snd, rqst_rcv) = mpsc::channel();
        spawn(move || {
            if let Err(e) = client_loop(client, stream, rqst_rcv) {
                error!("Error {:?} occurred when running backend task", e)
            }
        });
        Self {
            channel_num: Arc::new(Mutex::new(U32Iter::default())),
            snd: rqst_snd,
        }
    }

    /// close the backend session and consume the session broker itself
    ///
    pub fn close(self) {
        info!("Client close");
        drop(self)
    }

    /// open a [ExecBroker] channel which can excute commands
    ///
    pub fn open_exec(&mut self) -> SshResult<ExecBroker> {
        let channel = self.open_channel()?;
        channel.exec()
    }

    /// open a [ScpBroker] channel which can download/upload files/directories
    ///
    #[cfg(feature = "scp")]
    pub fn open_scp(&mut self) -> SshResult<ScpBroker> {
        let channel = self.open_channel()?;
        channel.scp()
    }

    /// open a [ShellBrocker] channel which  can be used as a pseudo terminal (AKA PTY)
    ///
    pub fn open_shell(&mut self) -> SshResult<ShellBrocker> {
        self.open_shell_terminal(TerminalSize::from(80, 24))
    }

    /// open a [ShellBrocker] channel
    ///
    /// custom terminal dimensions
    ///
    pub fn open_shell_terminal(&mut self, tv: TerminalSize) -> SshResult<ShellBrocker> {
        let channel = self.open_channel()?;
        channel.shell(tv)
    }

    /// open a raw channel
    ///
    /// need call `.exec()`, `.shell()`, `.scp()` and so on to convert it to a specific channel
    ///
    pub fn open_channel(&mut self) -> SshResult<ChannelBroker> {
        let (resp_send, resp_recv) = mpsc::channel();
        let client_id = self.channel_num.lock().unwrap().next().unwrap();

        // open channel request
        let mut data = Data::new();
        data.put_u8(ssh_connection_code::CHANNEL_OPEN)
            .put_str(ssh_str::SESSION)
            .put_u32(client_id)
            .put_u32(size::LOCAL_WINDOW_SIZE)
            .put_u32(size::BUF_SIZE as u32);

        self.snd
            .send(BackendRqst::OpenChannel(client_id, data, resp_send))?;

        // get the response
        match resp_recv.recv() {
            Ok(resp) => match resp {
                BackendResp::Ok(server_id) => Ok(ChannelBroker::new(
                    client_id,
                    server_id,
                    resp_recv,
                    self.snd.clone(),
                )),
                BackendResp::Fail(msg) => Err(SshError::GeneralError(msg)),
                _ => unreachable!(),
            },
            Err(e) => Err(e.into()),
        }
    }
}

fn client_loop<S>(mut client: Client, mut stream: S, rcv: Receiver<BackendRqst>) -> SshResult<()>
where
    S: Read + Write,
{
    let mut channels = HashMap::<u32, BackendChannel>::new();
    let mut pendings = HashMap::<u32, Sender<BackendResp>>::new();
    client.set_timeout(None);
    loop {
        let try_recv = rcv.try_recv();
        if try_recv.is_err() {
            if let Err(TryRecvError::Disconnected) = try_recv {
                info!("Session backend Closed");
                return Ok(());
            }
        } else if let Ok(rqst) = try_recv {
            match rqst {
                BackendRqst::OpenChannel(id, data, sender) => {
                    info!("try open channel {}.", id);

                    data.pack(&mut client).write_stream(&mut stream)?;

                    // add to pending open list
                    assert!(pendings.insert(id, sender).is_none());
                }
                BackendRqst::Data(id, data) => {
                    let channel = channels.get_mut(&id).unwrap();

                    trace!("Channel {} send {} data", id, data.len());
                    channel.send_data(data, &mut client, &mut stream)?;
                }
                BackendRqst::Command(id, data) => {
                    let channel = channels.get_mut(&id).unwrap();

                    trace!("Channel {} send control data", id);
                    channel.send(data, &mut client, &mut stream)?;
                }
                BackendRqst::CloseChannel(id, data) => {
                    info!("try close channel {}.", id);

                    let channel = channels.get_mut(&id).unwrap();
                    channel.send(data, &mut client, &mut stream)?;
                    channel.local_close()?;
                    if channel.is_close() {
                        channels.remove(&id);
                    }
                }
            }
        }

        if let Some(pkt) = SecPacket::try_from_stream(&mut stream, &mut client)? {
            let mut data = Data::unpack(pkt)?;
            let message_code = data.get_u8();

            match message_code {
                // Successfully open a channel
                ssh_connection_code::CHANNEL_OPEN_CONFIRMATION => {
                    let client_channel_no = data.get_u32();
                    let server_channel_no = data.get_u32();
                    let remote_window_size = data.get_u32();
                    // remote packet size, currently don't need it
                    data.get_u32();

                    // remove from pending open list
                    let sender = pendings.remove(&client_channel_no);
                    assert!(sender.is_some());

                    // add to opened list
                    assert!(channels
                        .insert(
                            client_channel_no,
                            BackendChannel::new(
                                server_channel_no,
                                client_channel_no,
                                remote_window_size,
                                sender.unwrap()
                            )?
                        )
                        .is_none())
                }
                /*
                    byte CHANNEL_OPEN_FAILURE
                    uint32 recipient channel
                    uint32 reason code
                    string description，ISO-10646 UTF-8 [RFC3629]
                    string language tag，[RFC3066]
                */
                // Fail to open a channel
                ssh_connection_code::CHANNEL_OPEN_FAILURE => {
                    //  client channel number
                    let id = data.get_u32();

                    let sender = pendings.remove(&id);
                    assert!(sender.is_some());
                    // error code
                    let code = data.get_u32();
                    // error detail: By default is utf-8
                    let description =
                        String::from_utf8(data.get_u8s()).unwrap_or_else(|_| String::from("error"));
                    // language tag, assume to be en-US
                    data.get_u8s();

                    let err_msg = match code {
                        ssh_channel_fail_code::ADMINISTRATIVELY_PROHIBITED => {
                            format!("ADMINISTRATIVELY_PROHIBITED: {description}")
                        }
                        ssh_channel_fail_code::CONNECT_FAILED => {
                            format!("CONNECT_FAILED: {description}")
                        }
                        ssh_channel_fail_code::UNKNOWN_CHANNEL_TYPE => {
                            format!("UNKNOWN_CHANNEL_TYPE: {description}")
                        }
                        ssh_channel_fail_code::RESOURCE_SHORTAGE => {
                            format!("RESOURCE_SHORTAGE: {description}")
                        }
                        _ => description,
                    };
                    sender.unwrap().send(BackendResp::Fail(err_msg))?;
                }
                ssh_transport_code::KEXINIT => {
                    data.insert(0, message_code);
                    let mut digest = Digest::new();
                    digest.hash_ctx.set_i_s(&data);
                    let server_algs = AlgList::unpack((data, &mut client).into())?;
                    client.key_agreement(&mut stream, server_algs, &mut digest)?;
                }
                ssh_connection_code::CHANNEL_DATA => {
                    let id = data.get_u32();
                    trace!("Channel {id} get {} data", data.len());
                    let channel = channels.get_mut(&id).unwrap();
                    channel.recv(data, &mut client, &mut stream)?;
                }
                ssh_connection_code::CHANNEL_EXTENDED_DATA => {
                    let id = data.get_u32();
                    let data_type = data.get_u32();
                    trace!(
                        "Channel {id} get {} extended data, type {data_type}",
                        data.len(),
                    );
                    let channel = channels.get_mut(&id).unwrap();
                    channel.recv(data, &mut client, &mut stream)?;
                }
                // flow_control msg
                ssh_connection_code::CHANNEL_WINDOW_ADJUST => {
                    // client channel number
                    let id = data.get_u32();
                    // to_add
                    let rws = data.get_u32();
                    let channel = channels.get_mut(&id).unwrap();
                    channel.recv_window_adjust(rws, &mut client, &mut stream)?;
                }
                ssh_connection_code::CHANNEL_CLOSE => {
                    let id = data.get_u32();
                    info!("Channel {} recv close", id);
                    let channel = channels.get_mut(&id).unwrap();
                    channel.remote_close()?;
                    if channel.is_close() {
                        channels.remove(&id);
                    }
                }
                ssh_connection_code::GLOBAL_REQUEST => {
                    let mut data = Data::new();
                    data.put_u8(ssh_connection_code::REQUEST_FAILURE);
                    data.pack(&mut client).write_stream(&mut stream)?;
                    continue;
                }

                x @ ssh_connection_code::CHANNEL_EOF => {
                    debug!("Currently ignore message {}", x);
                }
                x @ ssh_connection_code::CHANNEL_REQUEST => {
                    debug!("Currently ignore message {}", x);
                }
                _x @ ssh_connection_code::CHANNEL_SUCCESS => {
                    let id = data.get_u32();
                    trace!("Channel {} control success", id);
                    let channel = channels.get_mut(&id).unwrap();
                    channel.success()?
                }
                ssh_connection_code::CHANNEL_FAILURE => {
                    let id = data.get_u32();
                    trace!("Channel {} control failed", id);
                    let channel = channels.get_mut(&id).unwrap();
                    channel.failed()?
                }

                x => {
                    debug!("Currently ignore message {}", x);
                }
            }
        }
    }
}
