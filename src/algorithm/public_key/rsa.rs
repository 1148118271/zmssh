use crate::algorithm::public_key::PublicKey as PubK;
use crate::model::Data;
use crate::SshError;
//use rsa::PublicKey;
use rsa::pkcs1v15::Pkcs1v15Sign;

pub(super) struct RsaSha256;

impl PubK for RsaSha256 {
    fn new() -> Self
    where
        Self: Sized,
    {
        Self
    }

    fn verify_signature(&self, ks: &[u8], message: &[u8], sig: &[u8]) -> Result<bool, SshError> {
        let mut data = Data::from(ks[4..].to_vec());
        data.get_u8s();

        let e = rsa::BigUint::from_bytes_be(data.get_u8s().as_slice());
        let n = rsa::BigUint::from_bytes_be(data.get_u8s().as_slice());
        let public_key = rsa::RsaPublicKey::new(n, e).unwrap();
        let scheme = Pkcs1v15Sign::new::<sha2::Sha256>();

        let digest = ring::digest::digest(&ring::digest::SHA256, message);
        let msg = digest.as_ref();

        Ok(public_key.verify(scheme, msg, sig).is_ok())
    }
}

pub(super) struct RsaSha512;

impl PubK for RsaSha512 {
    fn new() -> Self
    where
        Self: Sized,
    {
        Self
    }

    fn verify_signature(&self, ks: &[u8], message: &[u8], sig: &[u8]) -> Result<bool, SshError> {
        let mut data = Data::from(ks[4..].to_vec());
        data.get_u8s();

        let e = rsa::BigUint::from_bytes_be(data.get_u8s().as_slice());
        let n = rsa::BigUint::from_bytes_be(data.get_u8s().as_slice());
        let public_key = rsa::RsaPublicKey::new(n, e).unwrap();
        let scheme = Pkcs1v15Sign::new::<sha2::Sha512>();

        let digest = ring::digest::digest(&ring::digest::SHA512, message);
        let msg = digest.as_ref();

        Ok(public_key.verify(scheme, msg, sig).is_ok())
    }
}

#[cfg(feature = "deprecated-rsa-sha1")]
pub(super) struct RsaSha1;
#[cfg(feature = "deprecated-rsa-sha1")]
impl PubK for RsaSha1 {
    fn new() -> Self
    where
        Self: Sized,
    {
        Self
    }

    fn verify_signature(&self, ks: &[u8], message: &[u8], sig: &[u8]) -> Result<bool, SshError> {
        let mut data = Data::from(ks[4..].to_vec());
        data.get_u8s();

        let e = rsa::BigUint::from_bytes_be(data.get_u8s().as_slice());
        let n = rsa::BigUint::from_bytes_be(data.get_u8s().as_slice());
        let public_key = rsa::RsaPublicKey::new(n, e).unwrap();
        let scheme = Pkcs1v15Sign::new::<sha1::Sha1>();

        let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, message);
        let msg = digest.as_ref();

        Ok(public_key.verify(scheme, msg, sig).is_ok())
    }
}
