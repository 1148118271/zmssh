use super::channel::Channel;
use crate::constant::{ssh_connection_code, ssh_str};
use crate::error::SshResult;
use crate::model::Data;
use std::{
    io::{Read, Write},
    ops::{Deref, DerefMut},
};

pub struct ChannelExec<S: Read + Write>(Channel<S>);

impl<S> ChannelExec<S>
where
    S: Read + Write,
{
    pub(crate) fn open(channel: Channel<S>) -> Self {
        ChannelExec(channel)
    }

    fn exec_command(&mut self, command: &str) -> SshResult<()> {
        tracing::debug!("Send command {}", command);
        let mut data = Data::new();
        data.put_u8(ssh_connection_code::CHANNEL_REQUEST)
            .put_u32(self.server_channel_no)
            .put_str(ssh_str::EXEC)
            .put_u8(true as u8)
            .put_str(command);
        self.send(data)
    }

    /// Send an executable command to the server
    /// and get the result
    ///
    /// This method also implicitly consume the channel object,
    /// since the exec channel can only execute one command
    ///
    pub fn send_command(mut self, command: &str) -> SshResult<Vec<u8>> {
        self.exec_command(command)?;

        let r = self.recv_to_end()?;
        Ok(r)
    }
}

impl<S> Deref for ChannelExec<S>
where
    S: Read + Write,
{
    type Target = Channel<S>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> DerefMut for ChannelExec<S>
where
    S: Read + Write,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
