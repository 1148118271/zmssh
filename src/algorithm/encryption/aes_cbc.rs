use crate::{
    algorithm::{hash::Hash, mac::Mac},
    SshError, SshResult,
};
use aes::{
    cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit},
    Aes128, Aes192, Aes256,
};
use cipher::generic_array::GenericArray;

use super::Encryption;

const CBC128_KEY_SIZE: usize = 16;
const CBC192_KEY_SIZE: usize = 24;
const CBC256_KEY_SIZE: usize = 32;
const IV_SIZE: usize = 16;
const BLOCK_SIZE: usize = 16;

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

macro_rules! crate_aes_cbc {
    ($name: ident, $alg: ident, $key_size: expr) => {
        pub(super) struct $name {
            pub(super) client_key: cbc::Encryptor<$alg>,
            pub(super) server_key: cbc::Decryptor<$alg>,
            extend: Extend,
        }

        impl Encryption for $name {
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
                let (ck, sk) = hash.mix_ek($key_size);
                let mut ckey = [0u8; $key_size];
                let mut skey = [0u8; $key_size];
                ckey.clone_from_slice(&ck[..$key_size]);
                skey.clone_from_slice(&sk[..$key_size]);

                let mut civ = [0u8; IV_SIZE];
                let mut siv = [0u8; IV_SIZE];
                civ.clone_from_slice(&hash.iv_c_s[..IV_SIZE]);
                siv.clone_from_slice(&hash.iv_s_c[..IV_SIZE]);

                let c = cbc::Encryptor::<$alg>::new(&ckey.into(), &civ.into());
                let r = cbc::Decryptor::<$alg>::new(&skey.into(), &siv.into());
                // hmac
                let (ik_c_s, ik_s_c) = hash.mix_ik(mac.bsize());
                $name {
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

            fn decrypt(
                &mut self,
                server_sequence_number: u32,
                buf: &mut [u8],
            ) -> SshResult<Vec<u8>> {
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
    };
}

// aes-128-cbc
crate_aes_cbc!(Cbc128, Aes128, CBC128_KEY_SIZE);
// aes-192-cbc
crate_aes_cbc!(Cbc192, Aes192, CBC192_KEY_SIZE);
// aes-256-cbc
crate_aes_cbc!(Cbc256, Aes256, CBC256_KEY_SIZE);
