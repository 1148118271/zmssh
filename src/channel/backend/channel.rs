use std::{
    io::{Read, Write},
    sync::mpsc::{Receiver, Sender},
    vec,
};

use crate::{
    client::Client,
    constant::ssh_connection_code,
    error::{SshError, SshResult},
    model::{BackendResp, BackendRqst, Data, FlowControl, Packet},
    TerminalSize,
};
use tracing::*;

#[cfg(feature = "scp")]
use super::channel_scp::ScpBroker;
use super::{channel_exec::ExecBroker, channel_shell::ShellBrocker};

pub(crate) struct Channel {
    snd: Sender<BackendResp>,
    server_channel_no: u32,
    client_channel_no: u32,
    remote_close: bool,
    local_close: bool,
    flow_control: FlowControl,
    pending_send: Vec<u8>,
}

impl Channel {
    pub fn new(
        server_channel_no: u32,
        client_channel_no: u32,
        remote_window: u32,
        snd: Sender<BackendResp>,
    ) -> SshResult<Self> {
        snd.send(BackendResp::Ok(server_channel_no))?;

        Ok(Self {
            snd,
            server_channel_no,
            client_channel_no,
            remote_close: false,
            local_close: false,
            flow_control: FlowControl::new(remote_window),
            pending_send: vec![],
        })
    }

    pub fn send_data<S>(&mut self, data: Data, client: &mut Client, stream: &mut S) -> SshResult<()>
    where
        S: Read + Write,
    {
        self.pending_send.append(&mut data.into_inner());
        self.try_send_data(client, stream)
    }

    fn try_send_data<S>(&mut self, client: &mut Client, stream: &mut S) -> SshResult<()>
    where
        S: Read + Write,
    {
        // try to send as much as we can
        while !self.pending_send.is_empty() {
            if self.flow_control.can_send() {
                let maybe_remain = self.flow_control.tune_on_send(&mut self.pending_send);

                // send it
                let mut data = Data::new();
                data.put_u8(ssh_connection_code::CHANNEL_DATA)
                    .put_u32(self.server_channel_no)
                    .put_u8s(&self.pending_send);

                // update remain
                self.pending_send = maybe_remain;

                self.send(data, client, stream)?;
            } else {
                break;
            }
        }
        Ok(())
    }

    pub fn send<S>(&mut self, data: Data, client: &mut Client, stream: &mut S) -> SshResult<()>
    where
        S: Read + Write,
    {
        if !self.closed() {
            data.pack(client).write_stream(stream)
        } else {
            Err(SshError::GeneralError(
                "Send data on a closed channel".to_owned(),
            ))
        }
    }

    pub fn recv<S>(&mut self, mut data: Data, client: &mut Client, stream: &mut S) -> SshResult<()>
    where
        S: Read + Write,
    {
        let mut buf = data.get_u8s();
        // flow_control
        self.flow_control.tune_on_recv(&mut buf);
        self.send_window_adjust(buf.len() as u32, client, stream)?;
        self.snd.send(BackendResp::Data(buf.into()))?;
        Ok(())
    }

    fn send_window_adjust<S>(
        &mut self,
        to_add: u32,
        client: &mut Client,
        stream: &mut S,
    ) -> SshResult<()>
    where
        S: Read + Write,
    {
        let mut data = Data::new();
        data.put_u8(ssh_connection_code::CHANNEL_WINDOW_ADJUST)
            .put_u32(self.server_channel_no)
            .put_u32(to_add);
        self.flow_control.on_send(to_add);
        self.send(data, client, stream)
    }

    pub fn recv_window_adjust<S>(
        &mut self,
        to_add: u32,
        client: &mut Client,
        stream: &mut S,
    ) -> SshResult<()>
    where
        S: Read + Write,
    {
        self.flow_control.on_recv(to_add);
        if !self.pending_send.is_empty() {
            self.try_send_data(client, stream)
        } else {
            Ok(())
        }
    }

    pub fn local_close(&mut self) -> SshResult<()> {
        trace!("Channel {} send local close", self.client_channel_no);
        self.local_close = true;
        Ok(())
    }

    pub fn remote_close(&mut self) -> SshResult<()> {
        trace!("Channel {} recv remote close", self.client_channel_no);
        self.remote_close = true;
        if !self.local_close {
            self.snd.send(BackendResp::Close)?;
        }
        Ok(())
    }

    pub fn success(&mut self) -> SshResult<()> {
        self.snd.send(BackendResp::Ok(self.client_channel_no))?;
        Ok(())
    }

    pub fn failed(&mut self) -> SshResult<()> {
        self.snd.send(BackendResp::Fail("".to_owned()))?;
        Ok(())
    }

    pub fn recv_rqst(&mut self, mut data: Data) -> SshResult<()> {
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
        Ok(())
    }

    fn handle_exit_status(&mut self, data: &mut Data) -> SshResult<()> {
        let maybe_false = data.get_u8();
        if maybe_false == 0 {
            self.snd.send(BackendResp::ExitStatus(data.get_u32()))?
        }
        Ok(())
    }

    fn handle_exit_signal(&mut self, data: &mut Data) -> SshResult<()> {
        let maybe_false = data.get_u8();
        let mut msg = "".to_owned();
        if maybe_false == 0 {
            if let Ok(sig_name) = String::from_utf8(data.get_u8s()) {
                msg += &format!("Current request is terminated by signal: {sig_name}\n");
            }
            let coredumped = data.get_u8();
            msg += &format!("Coredumped: {}\n", {
                if coredumped == 0 {
                    "False"
                } else {
                    "True"
                }
            });
            if let Ok(err_msg) = String::from_utf8(data.get_u8s()) {
                msg += &format!("Error message:\n{err_msg}\n");
            }
        }
        self.snd.send(BackendResp::TermMsg(msg))?;
        Ok(())
    }

    pub fn closed(&self) -> bool {
        self.local_close && self.remote_close
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        info!("Channel {} closed", self.client_channel_no);
    }
}

pub struct ChannelBroker {
    pub(crate) client_channel_no: u32,
    pub(crate) server_channel_no: u32,
    pub(crate) rcv: Receiver<BackendResp>,
    pub(crate) snd: Sender<BackendRqst>,
    pub(crate) close: bool,
    pub(crate) exit_status: u32,
    pub(crate) terminate_msg: String,
}

impl ChannelBroker {
    pub(crate) fn new(
        client_id: u32,
        server_id: u32,
        rcv: Receiver<BackendResp>,
        snd: Sender<BackendRqst>,
    ) -> Self {
        Self {
            client_channel_no: client_id,
            server_channel_no: server_id,
            rcv,
            snd,
            close: false,
            exit_status: 0,
            terminate_msg: "".to_owned(),
        }
    }

    /// open a [ExecBroker] channel which can excute commands
    ///
    pub fn exec(self) -> SshResult<ExecBroker> {
        Ok(ExecBroker::open(self))
    }

    /// open a [ScpBroker] channel which can download/upload files/directories
    ///
    #[cfg(feature = "scp")]
    pub fn scp(self) -> SshResult<ScpBroker> {
        Ok(ScpBroker::open(self))
    }

    /// open a [ShellBrocker] channel which  can be used as a pseudo terminal (AKA PTY)
    ///
    pub fn shell(self, tv: TerminalSize) -> SshResult<ShellBrocker> {
        ShellBrocker::open(self, tv)
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

    /// close the backend channel but do not consume
    ///
    pub fn close(&mut self) -> SshResult<()> {
        if !self.close {
            let mut data = Data::new();
            data.put_u8(ssh_connection_code::CHANNEL_CLOSE)
                .put_u32(self.server_channel_no);
            self.close = true;
            self.snd
                .send(BackendRqst::CloseChannel(self.client_channel_no, data))?;
        }
        Ok(())
    }

    pub(super) fn send_data(&self, data: Data) -> SshResult<()> {
        self.snd
            .send(BackendRqst::Data(self.client_channel_no, data))?;
        Ok(())
    }

    pub(super) fn send(&self, data: Data) -> SshResult<()> {
        self.snd
            .send(BackendRqst::Command(self.client_channel_no, data))?;
        if !self.close {
            match self.rcv.recv()? {
                BackendResp::Ok(_) => trace!("{}: control command ok", self.client_channel_no),
                BackendResp::Fail(msg) => error!(
                    "{}: channel error with reason {}",
                    self.client_channel_no, msg
                ),
                _ => unreachable!(),
            }
        }
        Ok(())
    }

    pub(super) fn recv(&mut self) -> SshResult<Vec<u8>> {
        if self.close {
            Ok(vec![])
        } else {
            match self.rcv.recv()? {
                BackendResp::Close => {
                    // the remote actively close their end
                    // but we can send close later when the broker get dropped
                    // just set a flag here
                    self.close = true;
                    Ok(vec![])
                }
                BackendResp::ExitStatus(status) => {
                    self.exit_status = status;
                    Ok(vec![])
                }
                BackendResp::TermMsg(msg) => {
                    self.terminate_msg = msg;
                    Ok(vec![])
                }
                BackendResp::Data(data) => Ok(data.into_inner()),
                _ => unreachable!(),
            }
        }
    }

    pub(super) fn try_recv(&mut self) -> SshResult<Option<Vec<u8>>> {
        if !self.close {
            if let Ok(resp) = self.rcv.try_recv() {
                match resp {
                    BackendResp::Close => {
                        // the remote actively close their end
                        // but we can send close later when the broker get dropped
                        // just set a flag here
                        self.close = true;
                        Ok(None)
                    }
                    BackendResp::Data(data) => Ok(Some(data.into_inner())),
                    BackendResp::ExitStatus(status) => {
                        self.exit_status = status;
                        Ok(None)
                    }
                    BackendResp::TermMsg(msg) => {
                        self.terminate_msg = msg;
                        Ok(None)
                    }
                    _ => unreachable!(),
                }
            } else {
                Ok(None)
            }
        } else {
            Err(SshError::GeneralError(
                "Read data on a closed channel".to_owned(),
            ))
        }
    }

    pub(super) fn recv_to_end(&mut self) -> SshResult<Vec<u8>> {
        let mut buf = vec![];
        while !self.close {
            buf.append(&mut self.recv()?);
        }
        Ok(buf)
    }
}

impl Drop for ChannelBroker {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
