use super::channel::Channel;
use crate::error::SshResult;
use crate::model::Data;
use crate::{
    constant::{ssh_connection_code, ssh_str},
    SshError,
};
use std::{
    io::{Read, Write},
    ops::{Deref, DerefMut},
};

pub struct ChannelExec<S: Read + Write> {
    channel: Channel<S>,
    command_send: bool,
}

impl<S> ChannelExec<S>
where
    S: Read + Write,
{
    pub(crate) fn open(channel: Channel<S>) -> Self {
        Self {
            channel,
            command_send: false,
        }
    }

    /// Send an executable command to the server
    ///
    pub fn exec_command(&mut self, command: &str) -> SshResult<()> {
        if self.command_send {
            return Err(SshError::GeneralError(
                "An exec channle can only send one command".to_owned(),
            ));
        }

        tracing::debug!("Send command {}", command);
        self.command_send = true;
        let mut data = Data::new();
        data.put_u8(ssh_connection_code::CHANNEL_REQUEST)
            .put_u32(self.server_channel_no)
            .put_str(ssh_str::EXEC)
            .put_u8(true as u8)
            .put_str(command);
        self.send(data)
    }

    /// Get the output of the previous command
    ///
    pub fn get_output(&mut self) -> SshResult<Vec<u8>> {
        let r: Vec<u8> = self.recv_to_end()?;
        Ok(r)
    }

    /// Send an executable command to the server
    /// and get the result
    ///
    /// This method also implicitly consume the channel object,
    /// since the exec channel can only execute one command
    ///
    pub fn send_command(mut self, command: &str) -> SshResult<Vec<u8>> {
        self.exec_command(command)?;

        self.get_output()
    }
}

impl<S> Deref for ChannelExec<S>
where
    S: Read + Write,
{
    type Target = Channel<S>;
    fn deref(&self) -> &Self::Target {
        &self.channel
    }
}

impl<S> DerefMut for ChannelExec<S>
where
    S: Read + Write,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.channel
    }
}
