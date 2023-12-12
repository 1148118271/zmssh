use super::channel::ChannelBroker;
use crate::constant::{ssh_connection_code, ssh_str};
use crate::error::SshResult;
use crate::model::Data;
use std::ops::{Deref, DerefMut};

pub struct ExecBroker(ChannelBroker);

impl ExecBroker {
    pub(crate) fn open(channel: ChannelBroker) -> Self {
        ExecBroker(channel)
    }

    /// Send an executable command to the server
    ///
    /// This method is non-block as it will not wait the result
    ///
    pub fn send_command(&self, command: &str) -> SshResult<()> {
        tracing::debug!("Send command {}", command);
        let mut data = Data::new();
        data.put_u8(ssh_connection_code::CHANNEL_REQUEST)
            .put_u32(self.server_channel_no)
            .put_str(ssh_str::EXEC)
            .put_u8(true as u8)
            .put_str(command);
        self.send(data)
    }

    /// Get the result of the prior command
    ///
    /// This method will block until the server close the channel
    ///
    /// This method also implicitly consume the channel object,
    /// since the exec channel can only execute one command
    ///
    pub fn get_result(mut self) -> SshResult<Vec<u8>> {
        self.recv_to_end()
    }
}

impl Deref for ExecBroker {
    type Target = ChannelBroker;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ExecBroker {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
