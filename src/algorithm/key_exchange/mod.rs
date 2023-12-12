use crate::algorithm::hash::HashType;
use crate::{SshError, SshResult};
use ring::agreement;
use ring::agreement::{EphemeralPrivateKey, UnparsedPublicKey};

/// # Algorithms that used for key exchange
///
/// <https://www.rfc-editor.org/rfc/rfc4253#section-7>
mod curve25519;
mod dh;
mod ecdh_sha2_nistp256;

use super::Kex;
use curve25519::CURVE25519;
#[cfg(feature = "deprecated-dh-group1-sha1")]
use dh::DiffieHellmanGroup1Sha1;
use dh::{DiffieHellmanGroup14Sha1, DiffieHellmanGroup14Sha256};
use ecdh_sha2_nistp256::EcdhP256;

pub(crate) trait KeyExchange: Send + Sync {
    fn new() -> SshResult<Self>
    where
        Self: Sized;
    fn get_public_key(&self) -> &[u8];
    fn get_shared_secret(&self, puk: Vec<u8>) -> SshResult<Vec<u8>>;
    fn get_hash_type(&self) -> HashType;
}

pub(crate) fn agree_ephemeral<B: AsRef<[u8]>>(
    private_key: EphemeralPrivateKey,
    peer_public_key: &UnparsedPublicKey<B>,
) -> SshResult<Vec<u8>> {
    match agreement::agree_ephemeral(private_key, peer_public_key, |key_material| {
        Ok(key_material.to_vec())
    }) {
        Ok(o) => o,
        Err(e) => Err(SshError::KexError(e.to_string())),
    }
}

pub(crate) fn from(s: &Kex) -> SshResult<Box<dyn KeyExchange>> {
    match s {
        Kex::Curve25519Sha256 => Ok(Box::new(CURVE25519::new()?)),
        Kex::EcdhSha2Nistrp256 => Ok(Box::new(EcdhP256::new()?)),
        #[cfg(feature = "deprecated-dh-group1-sha1")]
        Kex::DiffieHellmanGroup1Sha1 => Ok(Box::new(DiffieHellmanGroup1Sha1::new()?)),
        Kex::DiffieHellmanGroup14Sha1 => Ok(Box::new(DiffieHellmanGroup14Sha1::new()?)),
        Kex::DiffieHellmanGroup14Sha256 => Ok(Box::new(DiffieHellmanGroup14Sha256::new()?)),
    }
}
