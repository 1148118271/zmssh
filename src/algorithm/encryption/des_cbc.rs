use crate::{
    algorithm::{hash::Hash, mac::Mac},
    SshError, SshResult,
};
use cipher::{generic_array::GenericArray, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use des::TdesEde3 as des;

use super::Encryption;

const KEY_SIZE: usize = 24;
const IV_SIZE: usize = 8;
const BLOCK_SIZE: usize = 8;

struct Extend {
    // hmac
    mac: Box<dyn Mac>,
    ik_c_s: Vec<u8>,
    ik_s_c: Vec<u8>,
}

impl Extend {
    fn from(mac: Box<dyn Mac>, ik_c_s: Vec<u8>, ik_s_c: Vec<u8>) -> Self {
        Extend {
            mac,
            ik_c_s,
            ik_s_c,
        }
    }
}

pub(super) struct Cbc {
    pub(super) client_key: cbc::Encryptor<des>,
    pub(super) server_key: cbc::Decryptor<des>,
    extend: Extend,
}

impl Encryption for Cbc {
    fn bsize(&self) -> usize {
        BLOCK_SIZE
    }

    fn iv_size(&self) -> usize {
        IV_SIZE
    }

    fn new(hash: Hash, mac: Box<dyn Mac>) -> Self
    where
        Self: Sized,
    {
        let (ck, sk) = hash.mix_ek(KEY_SIZE);
        let mut ckey = [0u8; KEY_SIZE];
        let mut skey = [0u8; KEY_SIZE];
        ckey.clone_from_slice(&ck[..KEY_SIZE]);
        skey.clone_from_slice(&sk[..KEY_SIZE]);

        let mut civ = [0u8; IV_SIZE];
        let mut siv = [0u8; IV_SIZE];
        civ.clone_from_slice(&hash.iv_c_s[..IV_SIZE]);
        siv.clone_from_slice(&hash.iv_s_c[..IV_SIZE]);

        let c = cbc::Encryptor::<des>::new(&ckey.into(), &civ.into());
        let r = cbc::Decryptor::<des>::new(&skey.into(), &siv.into());
        // hmac
        let (ik_c_s, ik_s_c) = hash.mix_ik(mac.bsize());
        Cbc {
            client_key: c,
            server_key: r,
            extend: Extend::from(mac, ik_c_s, ik_s_c),
        }
    }

    fn encrypt(&mut self, client_sequence_num: u32, buf: &mut Vec<u8>) {
        let len = buf.len();
        let tag = self
            .extend
            .mac
            .sign(&self.extend.ik_c_s, client_sequence_num, buf);
        let mut idx = 0;
        while idx < len {
            let mut block = GenericArray::clone_from_slice(&buf[idx..idx + BLOCK_SIZE]);
            self.client_key.encrypt_block_mut(&mut block);
            buf[idx..idx + BLOCK_SIZE].clone_from_slice(&block);

            idx += BLOCK_SIZE;
        }
        buf.extend(tag.as_ref())
    }

    fn decrypt(&mut self, server_sequence_number: u32, buf: &mut [u8]) -> SshResult<Vec<u8>> {
        let pl = self.packet_len(server_sequence_number, buf);
        let data = &mut buf[..(pl + self.extend.mac.bsize())];
        let (d, m) = data.split_at_mut(pl);

        let len = d.len();
        let mut idx = 0;
        while idx < len {
            let mut block = GenericArray::clone_from_slice(&d[idx..idx + BLOCK_SIZE]);
            self.server_key.decrypt_block_mut(&mut block);
            d[idx..idx + BLOCK_SIZE].clone_from_slice(&block);

            idx += BLOCK_SIZE;
        }

        let tag = self
            .extend
            .mac
            .sign(&self.extend.ik_s_c, server_sequence_number, d);
        let t = tag.as_ref();
        if m != t {
            return Err(SshError::EncryptionError(
                "Failed to decrypt the server traffic".to_owned(),
            ));
        }
        Ok(d.to_vec())
    }

    fn packet_len(&mut self, _: u32, buf: &[u8]) -> usize {
        let mut block = GenericArray::clone_from_slice(&buf[..BLOCK_SIZE]);
        self.server_key.clone().decrypt_block_mut(&mut block);
        let packet_len = u32::from_be_bytes(block[..4].try_into().unwrap());
        (packet_len + 4) as usize
    }

    fn data_len(&mut self, server_sequence_number: u32, buf: &[u8]) -> usize {
        let pl = self.packet_len(server_sequence_number, buf);
        let bsize = self.extend.mac.bsize();
        pl + bsize
    }

    fn no_pad(&self) -> bool {
        false
    }
}
