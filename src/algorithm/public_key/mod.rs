use crate::SshError;

#[cfg(feature = "deprecated-dss-sha1")]
mod dss;
mod ed25519;
mod rsa;

#[cfg(feature = "deprecated-dss-sha1")]
use self::dss::DssSha1;
#[cfg(feature = "deprecated-rsa-sha1")]
use self::rsa::RsaSha1;
use self::rsa::RsaSha256;
use self::rsa::RsaSha512;
use super::PubKey;
use ed25519::Ed25519;

/// # Public Key Algorithms
///
/// <https://www.rfc-editor.org/rfc/rfc4253#section-6.6>

pub(crate) trait PublicKey: Send + Sync {
    fn new() -> Self
    where
        Self: Sized;
    fn verify_signature(&self, ks: &[u8], message: &[u8], sig: &[u8]) -> Result<bool, SshError>;
}

pub(crate) fn from(s: &PubKey) -> Box<dyn PublicKey> {
    match s {
        PubKey::SshEd25519 => Box::new(Ed25519::new()),
        #[cfg(feature = "deprecated-rsa-sha1")]
        PubKey::SshRsa => Box::new(RsaSha1::new()),
        PubKey::RsaSha2_256 => Box::new(RsaSha256::new()),
        PubKey::RsaSha2_512 => Box::new(RsaSha512::new()),
        #[cfg(feature = "deprecated-dss-sha1")]
        PubKey::SshDss => Box::new(DssSha1::new()),
    }
}
