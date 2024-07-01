use super::channel::ChannelBroker;
use crate::error::SshResult;
use crate::model::Data;
use crate::{
    constant::{ssh_connection_code, ssh_str},
    SshError,
};
use std::ops::{Deref, DerefMut};

pub struct ExecBroker {
    channel: ChannelBroker,
    command_send: bool,
}

impl ExecBroker {
    pub(crate) fn open(channel: ChannelBroker) -> Self {
        Self {
            channel,
            command_send: false,
        }
    }

    /// Send an executable command to the server
    ///
    /// This method is non-block as it will not wait the result
    ///
    pub fn send_command(&mut self, command: &str) -> SshResult<()> {
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

    /// Get the result of the prior command
    ///
    /// This method will block until the server close the channel
    ///
    pub fn get_result(&mut self) -> SshResult<Vec<u8>> {
        self.recv_to_end()
    }
}

impl Deref for ExecBroker {
    type Target = ChannelBroker;
    fn deref(&self) -> &Self::Target {
        &self.channel
    }
}

impl DerefMut for ExecBroker {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.channel
    }
}
