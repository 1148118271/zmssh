use crate::{
    algorithm::compression::{CompressNone, Compression},
    config::algorithm::AlgList,
};
use crate::{algorithm::encryption::Encryption, config::Config};
use crate::{algorithm::encryption::EncryptionNone, model::Sequence};
use std::time::Duration;

// the underlay connection
pub(crate) struct Client {
    pub(super) sequence: Sequence,
    pub(super) config: Config,
    pub(super) negotiated: AlgList,
    pub(super) encryptor: Box<dyn Encryption>,
    pub(super) compressor: Box<dyn Compression>,
    pub(super) session_id: Vec<u8>,
}

impl Client {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            encryptor: Box::<EncryptionNone>::default(),
            compressor: Box::<CompressNone>::default(),
            negotiated: AlgList::new(),
            session_id: vec![],
            sequence: Sequence::new(),
        }
    }

    pub fn get_encryptor(&mut self) -> &mut dyn Encryption {
        self.encryptor.as_mut()
    }

    pub fn get_compressor(&mut self) -> &mut dyn Compression {
        self.compressor.as_mut()
    }

    pub fn get_seq(&mut self) -> &mut Sequence {
        &mut self.sequence
    }

    pub fn get_timeout(&self) -> Option<Duration> {
        self.config.timeout
    }

    pub fn set_timeout(&mut self, tm: Option<Duration>) {
        self.config.timeout = tm
    }
}
