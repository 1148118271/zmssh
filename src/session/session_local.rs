use std::{
    cell::RefCell,
    io::{Read, Write},
    rc::Rc,
    time::Duration,
};
use tracing::*;

#[cfg(feature = "scp")]
use crate::channel::LocalScp;
use crate::{
    channel::{LocalChannel, LocalExec, LocalShell},
    client::Client,
    constant::{size, ssh_channel_fail_code, ssh_connection_code, ssh_str},
    error::{SshError, SshResult},
    model::TerminalSize,
    model::{Data, Packet, RcMut, SecPacket, U32Iter},
    LocalSftp,
};

pub struct LocalSession<S>
where
    S: Read + Write,
{
    client: RcMut<Client>,
    stream: RcMut<S>,
    channel_num: U32Iter,
}

impl<S> LocalSession<S>
where
    S: Read + Write,
{
    pub(crate) fn new(client: Client, stream: S) -> Self {
        Self {
            client: Rc::new(RefCell::new(client)),
            stream: Rc::new(RefCell::new(stream)),
            channel_num: U32Iter::default(),
        }
    }

    /// close the local session and consume it
    ///
    pub fn close(self) {
        info!("Client close");
        drop(self)
    }

    /// Modify the timeout setting
    /// in case the user wants to change the timeout during ssh operations.
    ///
    pub fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.client.borrow_mut().set_timeout(timeout)
    }

    /// open a [LocalExec] channel which can excute commands
    ///
    pub fn open_exec(&mut self) -> SshResult<LocalExec<S>> {
        let channel = self.open_channel()?;
        channel.exec()
    }

    /// open a [LocalScp] channel which can download/upload files/directories
    ///
    #[cfg(feature = "scp")]
    pub fn open_scp(&mut self) -> SshResult<LocalScp<S>> {
        let channel = self.open_channel()?;
        channel.scp()
    }

    /// open a [LocalShell] channel which can download/upload files/directories
    ///
    pub fn open_shell(&mut self) -> SshResult<LocalShell<S>> {
        self.open_shell_terminal(TerminalSize::from(80, 24))
    }

    /// open a [LocalShell] channel
    ///
    /// custom terminal dimensions
    ///
    pub fn open_shell_terminal(&mut self, tv: TerminalSize) -> SshResult<LocalShell<S>> {
        let channel = self.open_channel()?;
        channel.shell(tv)
    }

    pub fn open_sftp(&mut self) -> SshResult<LocalSftp<S>> {
        let channel = self.open_channel()?;
        channel.sftp()
    }

    pub fn get_raw_io(&mut self) -> RcMut<S> {
        self.stream.clone()
    }

    /// open a raw channel
    ///
    /// need call `.exec()`, `.shell()`, `.scp()` and so on to convert it to a specific channel
    ///
    pub fn open_channel(&mut self) -> SshResult<LocalChannel<S>> {
        info!("channel opened.");

        let client_channel_no = self.channel_num.next().unwrap();
        self.send_open_channel(client_channel_no)?;
        let (server_channel_no, remote_window_size) = self.receive_open_channel()?;

        Ok(LocalChannel::new(
            server_channel_no,
            client_channel_no,
            remote_window_size,
            self.client.clone(),
            self.stream.clone(),
        ))
    }

    // open channel request
    fn send_open_channel(&mut self, client_channel_no: u32) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(ssh_connection_code::CHANNEL_OPEN)
            .put_str(ssh_str::SESSION)
            .put_u32(client_channel_no)
            .put_u32(size::LOCAL_WINDOW_SIZE)
            .put_u32(size::BUF_SIZE as u32);
        data.pack(&mut self.client.borrow_mut())
            .write_stream(&mut *self.stream.borrow_mut())
    }

    // get the response of the channel request
    fn receive_open_channel(&mut self) -> SshResult<(u32, u32)> {
        loop {
            let mut data = Data::unpack(SecPacket::from_stream(
                &mut *self.stream.borrow_mut(),
                &mut self.client.borrow_mut(),
            )?)?;

            let message_code = data.get_u8();
            match message_code {
                // Successfully open a channel
                ssh_connection_code::CHANNEL_OPEN_CONFIRMATION => {
                    data.get_u32();
                    let server_channel_no = data.get_u32();
                    let remote_window_size = data.get_u32();
                    // remote packet size, currently don't need it
                    data.get_u32();
                    return Ok((server_channel_no, remote_window_size));
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
                    data.get_u32();
                    // error code
                    let code = data.get_u32();
                    // error detail: By default is utf-8
                    let description =
                        String::from_utf8(data.get_u8s()).unwrap_or_else(|_| String::from("error"));
                    // language tag, assume to be en-US
                    data.get_u8s();

                    let err_msg = match code {
                        ssh_channel_fail_code::ADMINISTRATIVELY_PROHIBITED => {
                            format!("ADMINISTRATIVELY_PROHIBITED: {}", description)
                        }
                        ssh_channel_fail_code::CONNECT_FAILED => {
                            format!("CONNECT_FAILED: {}", description)
                        }
                        ssh_channel_fail_code::UNKNOWN_CHANNEL_TYPE => {
                            format!("UNKNOWN_CHANNEL_TYPE: {}", description)
                        }
                        ssh_channel_fail_code::RESOURCE_SHORTAGE => {
                            format!("RESOURCE_SHORTAGE: {}", description)
                        }
                        _ => description,
                    };
                    return Err(SshError::GeneralError(err_msg));
                }
                ssh_connection_code::GLOBAL_REQUEST => {
                    let mut data = Data::new();
                    data.put_u8(ssh_connection_code::REQUEST_FAILURE);
                    data.pack(&mut self.client.borrow_mut())
                        .write_stream(&mut *self.stream.borrow_mut())?;
                    continue;
                }
                x => {
                    debug!("Ignore ssh msg {}", x);
                    continue;
                }
            }
        }
    }
}
