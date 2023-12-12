use crate::algorithm::hash::Hash;
use crate::algorithm::mac::Mac;
use crate::error::SshError;
use crate::{algorithm::encryption::Encryption, error::SshResult};
use ring::aead::chacha20_poly1305_openssh::{OpeningKey, SealingKey};

const KEY_SIZE: usize = 64;
const IV_SIZE: usize = 0;
const BLOCK_SIZE: usize = 0;
const MAC_SIZE: usize = 16;

pub(super) struct ChaCha20Poly1305 {
    client_key: SealingKey,
    server_key: OpeningKey,
}

impl Encryption for ChaCha20Poly1305 {
    fn bsize(&self) -> usize {
        BLOCK_SIZE
    }

    fn iv_size(&self) -> usize {
        IV_SIZE
    }

    fn new(hash: Hash, _mac: Box<dyn Mac>) -> ChaCha20Poly1305 {
        let (ck, sk) = hash.mix_ek(KEY_SIZE);
        let mut sealing_key = [0_u8; KEY_SIZE];
        let mut opening_key = [0_u8; KEY_SIZE];
        sealing_key.copy_from_slice(&ck);
        opening_key.copy_from_slice(&sk);

        ChaCha20Poly1305 {
            client_key: SealingKey::new(&sealing_key),
            server_key: OpeningKey::new(&opening_key),
        }
    }

    fn encrypt(&mut self, sequence_number: u32, buf: &mut Vec<u8>) {
        let mut tag = [0_u8; MAC_SIZE];
        self.client_key
            .seal_in_place(sequence_number, buf, &mut tag);
        buf.append(&mut tag.to_vec());
    }

    fn decrypt(&mut self, sequence_number: u32, buf: &mut [u8]) -> SshResult<Vec<u8>> {
        let mut packet_len_slice = [0_u8; 4];
        let len = &buf[..4];
        packet_len_slice.copy_from_slice(len);
        let packet_len_slice = self
            .server_key
            .decrypt_packet_length(sequence_number, packet_len_slice);
        let packet_len = u32::from_be_bytes(packet_len_slice);
        let (buf, tag_) = buf.split_at_mut((packet_len + 4) as usize);
        let mut tag = [0_u8; MAC_SIZE];
        tag.copy_from_slice(tag_);
        match self.server_key.open_in_place(sequence_number, buf, &tag) {
            Ok(result) => Ok([&packet_len_slice[..], result].concat()),
            Err(_) => Err(SshError::EncryptionError(
                "Failed to decrypt the server traffic".to_owned(),
            )),
        }
    }

    fn packet_len(&mut self, sequence_number: u32, buf: &[u8]) -> usize {
        let mut packet_len_slice = [0_u8; 4];
        packet_len_slice.copy_from_slice(&buf[..4]);
        let packet_len_slice = self
            .server_key
            .decrypt_packet_length(sequence_number, packet_len_slice);
        u32::from_be_bytes(packet_len_slice) as usize + 4
    }

    fn data_len(&mut self, sequence_number: u32, buf: &[u8]) -> usize {
        let packet_len = self.packet_len(sequence_number, buf);
        packet_len + MAC_SIZE
    }

    fn no_pad(&self) -> bool {
        true
    }
}
