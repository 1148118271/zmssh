#[cfg(feature = "deprecated-aes-cbc")]
mod aes_cbc;
mod aes_ctr;
mod chacha20_poly1305_openssh;
#[cfg(feature = "deprecated-des-cbc")]
mod des_cbc;

use crate::algorithm::hash::Hash;
use crate::algorithm::mac::Mac;
use crate::SshResult;

use super::{hash::HashCtx, mac::MacNone, Enc};

/// <https://www.rfc-editor.org/rfc/rfc4253#section-6.3>
pub(crate) trait Encryption: Send + Sync {
    fn bsize(&self) -> usize;
    fn iv_size(&self) -> usize;
    fn new(hash: Hash, mac: Box<dyn Mac>) -> Self
    where
        Self: Sized;
    fn encrypt(&mut self, client_sequence_num: u32, buf: &mut Vec<u8>);
    fn decrypt(&mut self, sequence_number: u32, buf: &mut [u8]) -> SshResult<Vec<u8>>;
    fn packet_len(&mut self, sequence_number: u32, buf: &[u8]) -> usize;
    fn data_len(&mut self, sequence_number: u32, buf: &[u8]) -> usize;
    fn no_pad(&self) -> bool;
}

pub(crate) fn from(s: &Enc, hash: Hash, mac: Box<dyn Mac>) -> Box<dyn Encryption> {
    match s {
        Enc::Chacha20Poly1305Openssh => {
            Box::new(chacha20_poly1305_openssh::ChaCha20Poly1305::new(hash, mac))
        }
        Enc::Aes128Ctr => Box::new(aes_ctr::Ctr128::new(hash, mac)),
        Enc::Aes192Ctr => Box::new(aes_ctr::Ctr192::new(hash, mac)),
        Enc::Aes256Ctr => Box::new(aes_ctr::Ctr256::new(hash, mac)),
        #[cfg(feature = "deprecated-aes-cbc")]
        Enc::Aes128Cbc => Box::new(aes_cbc::Cbc128::new(hash, mac)),
        #[cfg(feature = "deprecated-aes-cbc")]
        Enc::Aes192Cbc => Box::new(aes_cbc::Cbc192::new(hash, mac)),
        #[cfg(feature = "deprecated-aes-cbc")]
        Enc::Aes256Cbc => Box::new(aes_cbc::Cbc256::new(hash, mac)),
        #[cfg(feature = "deprecated-des-cbc")]
        Enc::TripleDesCbc => Box::new(des_cbc::Cbc::new(hash, mac)),
    }
}

pub(crate) struct EncryptionNone {}

impl Encryption for EncryptionNone {
    fn bsize(&self) -> usize {
        8
    }
    fn iv_size(&self) -> usize {
        8
    }

    fn new(_hash: Hash, _mac: Box<dyn Mac>) -> Self
    where
        Self: Sized,
    {
        Self {}
    }
    fn encrypt(&mut self, _client_sequence_num: u32, _buf: &mut Vec<u8>) {
        // do nothing
    }
    fn decrypt(&mut self, _sequence_number: u32, buf: &mut [u8]) -> SshResult<Vec<u8>> {
        Ok(buf.to_vec())
    }
    fn packet_len(&mut self, _sequence_number: u32, buf: &[u8]) -> usize {
        u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize
    }
    fn data_len(&mut self, sequence_number: u32, buf: &[u8]) -> usize {
        self.packet_len(sequence_number, buf) + 4
    }
    fn no_pad(&self) -> bool {
        false
    }
}

impl Default for EncryptionNone {
    fn default() -> Self {
        let hash = Hash::new(HashCtx::new(), &[], super::hash::HashType::None);
        let mac = Box::new(MacNone::new());
        Self::new(hash, mac)
    }
}
