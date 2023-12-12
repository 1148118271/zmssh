#[cfg(feature = "deprecated-dss-sha1")]
use sha1::{Digest, Sha1};
use signature::DigestVerifier;

use crate::algorithm::public_key::PublicKey as PubK;
use crate::model::Data;
use crate::SshError;

#[cfg(feature = "deprecated-dss-sha1")]
pub(super) struct DssSha1;

#[cfg(feature = "deprecated-dss-sha1")]
impl PubK for DssSha1 {
    fn new() -> Self
    where
        Self: Sized,
    {
        Self
    }

    fn verify_signature(&self, ks: &[u8], message: &[u8], sig: &[u8]) -> Result<bool, SshError> {
        let mut data = Data::from(ks[4..].to_vec());
        data.get_u8s();

        // RFC4253 6.6 DSS Signature key blob are 4x mpint's that need to be pulled out to be used as components in the public key.
        let p = dsa::BigUint::from_bytes_be(data.get_u8s().as_slice());
        let q = dsa::BigUint::from_bytes_be(data.get_u8s().as_slice());
        let g = dsa::BigUint::from_bytes_be(data.get_u8s().as_slice());
        let y = dsa::BigUint::from_bytes_be(data.get_u8s().as_slice());

        let components = dsa::Components::from_components(p, q, g).map_err(|_| {
            SshError::SshPubKeyError("SSH Public Key components were not valid".to_string())
        })?;

        // Build the public key for verification of the message
        let public_key = dsa::VerifyingKey::from_components(components, y).map_err(|_| {
            SshError::SshPubKeyError("SSH Public Key components were not valid".to_string())
        })?;

        // Perform an SHA1 hash on the message
        let digest = Sha1::new().chain_update(message);

        // RFC4253 6.6 DSS Signature blob is actually 2x160bit blobs so r and s are each 160bit (20 bytes)
        let r = dsa::BigUint::from_bytes_be(&sig[0..20]);
        let s = dsa::BigUint::from_bytes_be(&sig[20..40]);

        let signature = dsa::Signature::from_components(r, s)
            .map_err(|_| SshError::SshPubKeyError("SSH Signature was not valid".to_string()))?;

        // Verify the hashed message with the provided signature, matches the public_key
        Ok(public_key.verify_digest(digest, &signature).is_ok())
    }
}
