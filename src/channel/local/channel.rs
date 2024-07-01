use std::io::{Read, Write};

use crate::{
    algorithm::Digest,
    client::Client,
    config::algorithm::AlgList,
    constant::ssh_connection_code,
    error::{SshError, SshResult},
    model::{Data, FlowControl, Packet, RcMut, SecPacket},
};
use crate::{constant::ssh_transport_code, model::TerminalSize};
use tracing::*;

#[cfg(feature = "scp")]
use super::ChannelScp;
use super::{ChannelExec, ChannelShell};

pub(super) enum ChannelRead {
    Data(Vec<u8>),
    Code(u8),
}

pub struct Channel<S>
where
    S: Read + Write,
{
    pub(crate) server_channel_no: u32,
    pub(crate) client_channel_no: u32,
    pub(crate) remote_close: bool,
    pub(crate) local_close: bool,
    pub(crate) flow_control: FlowControl,
    pub(crate) client: RcMut<Client>,
    pub(crate) stream: RcMut<S>,
    pub(crate) exit_status: u32,
    pub(crate) terminate_msg: String,
}

impl<S> Channel<S>
where
    S: Read + Write,
{
    pub(crate) fn new(
        server_channel_no: u32,
        client_channel_no: u32,
        remote_window: u32,
        client: RcMut<Client>,
        stream: RcMut<S>,
    ) -> Self {
        Self {
            server_channel_no,
            client_channel_no,
            remote_close: false,
            local_close: false,
            flow_control: FlowControl::new(remote_window),
            client,
            stream,
            exit_status: 0,
            terminate_msg: "".to_owned(),
        }
    }

    /// convert the raw channel to an [self::ChannelExec]
    ///
    pub fn exec(self) -> SshResult<ChannelExec<S>> {
        info!("exec opened.");
        Ok(ChannelExec::open(self))
    }

    /// convert the raw channel to an [self::ChannelScp]
    ///
    #[cfg(feature = "scp")]
    pub fn scp(self) -> SshResult<ChannelScp<S>> {
        info!("scp opened.");
        Ok(ChannelScp::open(self))
    }

    /// convert the raw channel to an [self::ChannelShell]
    ///
    /// with `row` lines & `column` characters per one line
    ///
    pub fn shell(self, tv: TerminalSize) -> SshResult<ChannelShell<S>> {
        info!("shell opened.");
        ChannelShell::open(self, tv)
    }

    /// close the channel gracefully, but do not consume it
    ///
    pub fn close(&mut self) -> SshResult<()> {
        info!("channel close.");
        self.send_close()?;
        self.receive_close()
    }

    /// <https://datatracker.ietf.org/doc/html/rfc4254#section-6.10>
    ///
    /// Return the command execute status
    ///
    pub fn exit_status(&self) -> SshResult<u32> {
        Ok(self.exit_status)
    }

    /// <https://datatracker.ietf.org/doc/html/rfc4254#section-6.10>
    ///
    /// Return the terminate message if the command excution was 'killed' by a signal
    ///
    pub fn terminate_msg(&self) -> SshResult<String> {
        Ok(self.terminate_msg.clone())
    }

    fn send_close(&mut self) -> SshResult<()> {
        if self.local_close {
            return Ok(());
        }
        let mut data = Data::new();
        data.put_u8(ssh_connection_code::CHANNEL_CLOSE)
            .put_u32(self.server_channel_no);
        self.local_close = true;
        self.send(data)
    }

    fn receive_close(&mut self) -> SshResult<()> {
        if self.remote_close {
            return Ok(());
        }
        let _ = self.recv_to_end()?;
        Ok(())
    }

    pub(super) fn send(&mut self, data: Data) -> SshResult<()> {
        data.pack(&mut self.client.borrow_mut())
            .write_stream(&mut *self.stream.borrow_mut())
    }

    // only send SSH_MSG_CHANNEL_DATA will call this,
    // for auto adjust the window size
    pub(super) fn send_data(&mut self, mut buf: Vec<u8>) -> SshResult<Vec<u8>> {
        let mut maybe_response = vec![];

        loop {
            // first adjust the data to the max size we can send
            let maybe_remain = self.flow_control.tune_on_send(&mut buf);

            // send it
            let mut data = Data::new();
            data.put_u8(ssh_connection_code::CHANNEL_DATA)
                .put_u32(self.server_channel_no)
                .put_u8s(&buf);
            self.send(data)?;

            if maybe_remain.is_empty() {
                // if all send, return
                break;
            } else {
                buf = maybe_remain
            }

            // otherwise wait the server to adjust its window
            while !self.flow_control.can_send() {
                let buf = self.recv_once()?;

                if let ChannelRead::Data(mut data) = buf {
                    maybe_response.append(&mut data);
                }
            }
        }

        Ok(maybe_response)
    }

    /// this method will receive at least one data packet
    ///
    pub(super) fn recv(&mut self) -> SshResult<Vec<u8>> {
        while !self.closed() {
            let maybe_recv = self.recv_once()?;

            if let ChannelRead::Data(data) = maybe_recv {
                return Ok(data);
            }
        }
        Ok(vec![])
    }

    pub(super) fn recv_to_end(&mut self) -> SshResult<Vec<u8>> {
        let mut resp = vec![];
        while !self.closed() {
            let mut read_this_time = self.recv()?;
            resp.append(&mut read_this_time);
        }
        Ok(resp)
    }

    pub(super) fn try_recv(&mut self) -> SshResult<Option<Vec<u8>>> {
        let data = {
            match SecPacket::try_from_stream(
                &mut *self.stream.borrow_mut(),
                &mut self.client.borrow_mut(),
            )? {
                Some(pkt) => Data::unpack(pkt)?,
                None => return Ok(None),
            }
        };
        if let ChannelRead::Data(d) = self.handle_msg(data)? {
            Ok(Some(d))
        } else {
            Ok(None)
        }
    }

    fn recv_once(&mut self) -> SshResult<ChannelRead> {
        let data = Data::unpack(SecPacket::from_stream(
            &mut *self.stream.borrow_mut(),
            &mut self.client.borrow_mut(),
        )?)?;
        self.handle_msg(data)
    }

    fn handle_msg(&mut self, mut data: Data) -> SshResult<ChannelRead> {
        let message_code = data.get_u8();
        match message_code {
            x @ ssh_transport_code::KEXINIT => {
                data.insert(0, message_code);
                let mut digest = Digest::new();
                digest.hash_ctx.set_i_s(&data);
                let server_algs = AlgList::unpack((data, &mut *self.client.borrow_mut()).into())?;
                self.client.borrow_mut().key_agreement(
                    &mut *self.stream.borrow_mut(),
                    server_algs,
                    &mut digest,
                )?;
                Ok(ChannelRead::Code(x))
            }
            x @ ssh_connection_code::CHANNEL_DATA => {
                let cc = data.get_u32();
                if cc == self.client_channel_no {
                    let mut data = data.get_u8s();

                    // flow_control
                    self.flow_control.tune_on_recv(&mut data);
                    self.send_window_adjust(data.len() as u32)?;

                    return Ok(ChannelRead::Data(data));
                }
                Ok(ChannelRead::Code(x))
            }
            x @ ssh_connection_code::CHANNEL_EXTENDED_DATA => {
                let cc = data.get_u32();
                if cc == self.client_channel_no {
                    let data_type_code = data.get_u32();
                    let mut data = data.get_u8s();

                    debug!("Recv extended data with type {data_type_code}");

                    // flow_contrl
                    self.flow_control.tune_on_recv(&mut data);
                    self.send_window_adjust(data.len() as u32)?;

                    return Ok(ChannelRead::Data(data));
                }
                Ok(ChannelRead::Code(x))
            }
            x @ ssh_connection_code::GLOBAL_REQUEST => {
                let mut data = Data::new();
                data.put_u8(ssh_connection_code::REQUEST_FAILURE);
                self.send(data)?;
                Ok(ChannelRead::Code(x))
            }
            x @ ssh_connection_code::CHANNEL_WINDOW_ADJUST => {
                data.get_u32();
                // to add
                let rws = data.get_u32();
                self.recv_window_adjust(rws)?;
                Ok(ChannelRead::Code(x))
            }
            x @ ssh_connection_code::CHANNEL_EOF => {
                debug!("Currently ignore message {}", x);
                Ok(ChannelRead::Code(x))
            }
            x @ ssh_connection_code::CHANNEL_REQUEST => {
                let cc = data.get_u32();
                if cc == self.client_channel_no {
                    let status: Vec<u8> = data.get_u8s();
                    if let Ok(status_string) = String::from_utf8(status.clone()) {
                        match status_string.as_str() {
                            "exit-status" => {
                                let _ = self.handle_exit_status(&mut data);
                            }
                            "exit-signal" => {
                                let _ = self.handle_exit_signal(&mut data);
                            }
                            s => {
                                debug!("Currently ignore request {}", s);
                            }
                        }
                    }
                }
                Ok(ChannelRead::Code(x))
            }
            x @ ssh_connection_code::CHANNEL_SUCCESS => {
                debug!("Currently ignore message {}", x);
                Ok(ChannelRead::Code(x))
            }
            ssh_connection_code::CHANNEL_FAILURE => {
                Err(SshError::GeneralError("channel failure.".to_owned()))
            }
            x @ ssh_connection_code::CHANNEL_CLOSE => {
                let cc = data.get_u32();
                if cc == self.client_channel_no {
                    self.remote_close = true;
                    self.send_close()?;
                }
                Ok(ChannelRead::Code(x))
            }
            x => {
                debug!("Currently ignore message {}", x);
                Ok(ChannelRead::Code(x))
            }
        }
    }

    fn handle_exit_status(&mut self, data: &mut Data) -> SshResult<()> {
        let maybe_false = data.get_u8();
        if maybe_false == 0 {
            self.exit_status = data.get_u32()
        }
        Ok(())
    }

    fn handle_exit_signal(&mut self, data: &mut Data) -> SshResult<()> {
        let maybe_false = data.get_u8();
        if maybe_false == 0 {
            let sig_name = String::from_utf8(data.get_u8s())?;
            self.terminate_msg += &format!("Current request is terminated by signal: {sig_name}\n");
            let coredumped = data.get_u8();
            self.terminate_msg += &format!("Coredumped: {}\n", {
                if coredumped == 0 {
                    "False"
                } else {
                    "True"
                }
            });
            let err_msg = String::from_utf8(data.get_u8s())?;
            self.terminate_msg += &format!("Error message:\n{err_msg}\n");
        }
        Ok(())
    }

    fn send_window_adjust(&mut self, to_add: u32) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(ssh_connection_code::CHANNEL_WINDOW_ADJUST)
            .put_u32(self.server_channel_no)
            .put_u32(to_add);
        self.flow_control.on_send(to_add);
        self.send(data)
    }

    fn recv_window_adjust(&mut self, to_add: u32) -> SshResult<()> {
        self.flow_control.on_recv(to_add);
        Ok(())
    }

    /// Return if the channel is closed
    ///
    pub fn closed(&self) -> bool {
        self.local_close && self.remote_close
    }
}
