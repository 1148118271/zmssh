use std::{
    fmt::{Debug, Display},
    ops::{Deref, DerefMut},
    str::FromStr,
};
use tracing::*;

use crate::{
    algorithm::{Compress, Enc, Kex, Mac, PubKey},
    client::Client,
    constant::ssh_transport_code,
    error::{SshError, SshResult},
    model::{Data, Packet, SecPacket},
    util,
};

macro_rules! create_wrapped_type {
    ($name: ident, $value_type: ty) => {
        #[derive(Clone, Default)]
        pub(crate) struct $name(Vec<$value_type>);
        impl Deref for $name {
            type Target = Vec<$value_type>;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl DerefMut for $name {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        impl Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "{}",
                    self.iter()
                        .map(|&x| x.as_ref().to_owned())
                        .collect::<Vec<String>>()
                        .join(",")
                )
            }
        }

        impl TryFrom<Vec<String>> for $name {
            type Error = SshError;
            fn try_from(v: Vec<String>) -> Result<Self, Self::Error> {
                let v = v
                    .iter()
                    .filter_map(|x| <$value_type>::from_str(x.as_str()).ok())
                    .collect::<Vec<$value_type>>();
                Ok(Self(v))
            }
        }

        impl From<Vec<$value_type>> for $name {
            fn from(v: Vec<$value_type>) -> Self {
                Self(v)
            }
        }
    };
}

create_wrapped_type!(Kexs, Kex);
create_wrapped_type!(PubKeys, PubKey);
create_wrapped_type!(Encs, Enc);
create_wrapped_type!(Macs, Mac);
create_wrapped_type!(Compresses, Compress);

#[derive(Clone, Default)]
pub(crate) struct AlgList {
    pub key_exchange: Kexs,
    pub public_key: PubKeys,
    pub c_encryption: Encs,
    pub s_encryption: Encs,
    pub c_mac: Macs,
    pub s_mac: Macs,
    pub c_compress: Compresses,
    pub s_compress: Compresses,
}

impl Debug for AlgList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "kex: \"{}\", ", self.key_exchange)?;
        write!(f, "pubkey: \"{}\", ", self.public_key)?;
        write!(f, "c_enc: \"{}\", ", self.c_encryption)?;
        write!(f, "s_enc: \"{}\", ", self.s_encryption)?;
        write!(f, "c_mac: \"{}\", ", self.c_mac)?;
        write!(f, "s_mac: \"{}\", ", self.s_mac)?;
        write!(f, "c_compress: \"{}\", ", self.c_compress)?;
        write!(f, "s_compress: \"{}\"", self.s_compress)
    }
}

impl AlgList {
    pub fn new() -> Self {
        AlgList {
            ..Default::default()
        }
    }

    pub fn client_default() -> Self {
        AlgList {
            key_exchange: vec![
                Kex::Curve25519Sha256,
                Kex::EcdhSha2Nistrp256,
                Kex::DiffieHellmanGroup14Sha256,
                Kex::DiffieHellmanGroup14Sha1,
            ]
            .into(),
            public_key: vec![PubKey::RsaSha2_512, PubKey::RsaSha2_256].into(),
            c_encryption: vec![
                Enc::Chacha20Poly1305Openssh,
                Enc::Aes128Ctr,
                Enc::Aes192Ctr,
                Enc::Aes256Ctr,
            ]
            .into(),
            s_encryption: vec![
                Enc::Chacha20Poly1305Openssh,
                Enc::Aes128Ctr,
                Enc::Aes192Ctr,
                Enc::Aes256Ctr,
            ]
            .into(),
            c_mac: vec![Mac::HmacSha2_256, Mac::HmacSha2_512, Mac::HmacSha1].into(),
            s_mac: vec![Mac::HmacSha2_256, Mac::HmacSha2_512, Mac::HmacSha1].into(),
            c_compress: vec![Compress::None, Compress::ZlibOpenSsh].into(),
            s_compress: vec![Compress::None, Compress::ZlibOpenSsh].into(),
        }
    }

    fn from(mut data: Data) -> SshResult<Self> {
        data.get_u8();
        // skip the 16-bit cookie
        data.skip(16);
        let mut server_algorithm = Self::new();

        macro_rules! try_convert {
            ($hint: literal, $field: ident) => {
                let alg_string = util::vec_u8_to_string(data.get_u8s(), ",")?;
                info!("server {}: {:?}", $hint, alg_string);
                server_algorithm.$field = alg_string.try_into()?;
            };
        }
        try_convert!("key exchange", key_exchange);
        try_convert!("public key", public_key);
        try_convert!("c2s encryption", c_encryption);
        try_convert!("s2c encryption", s_encryption);
        try_convert!("c2s mac", c_mac);
        try_convert!("s2c mac", s_mac);
        try_convert!("c2s compression", c_compress);
        try_convert!("s2c compression", s_compress);
        debug!("converted server algorithms: [{:?}]", server_algorithm);
        Ok(server_algorithm)
    }

    pub fn match_with(&self, other: &Self) -> SshResult<Self> {
        macro_rules! match_field {
            ($our: expr,  $their:expr, $field: ident, $err_hint: literal) => {
                $our.$field
                    .iter()
                    .find_map(|k| {
                        if $their.$field.contains(k) {
                            Some(k)
                        } else {
                            None
                        }
                    })
                    .ok_or_else(|| {
                        let err_msg = format!(
                            "Key_agreement: the {} fails to match, \
                        algorithms supported by the server: {},\
                        algorithms supported by the client: {}",
                            $err_hint, $their.$field, $our.$field
                        );
                        error!(err_msg);
                        SshError::KexError(err_msg)
                    })
            };
        }

        // kex
        let kex = match_field!(self, other, key_exchange, "DH algorithm")?;
        // pubkey
        let pubkey = match_field!(self, other, public_key, "signature algorithm")?;
        // encryption
        let c_enc = match_field!(self, other, c_encryption, "client encryption algorithm")?;
        let s_enc = match_field!(self, other, s_encryption, "server encryption algorithm")?;

        // mac
        let c_mac = match_field!(self, other, c_mac, "client mac algorithm")?;
        let s_mac = match_field!(self, other, s_mac, "server mac algorithm")?;

        // compress
        let c_compress = match_field!(self, other, c_compress, "client compression algorithm")?;
        let s_compress = match_field!(self, other, s_compress, "server compression algorithm")?;

        let negotiated = Self {
            key_exchange: vec![*kex].into(),
            public_key: vec![*pubkey].into(),
            c_encryption: vec![*c_enc].into(),
            s_encryption: vec![*s_enc].into(),
            c_mac: vec![*c_mac].into(),
            s_mac: vec![*s_mac].into(),
            c_compress: vec![*c_compress].into(),
            s_compress: vec![*s_compress].into(),
        };

        info!("matched algorithms [{:?}]", negotiated);

        Ok(negotiated)
    }

    fn as_i(&self) -> Vec<u8> {
        let mut data = Data::new();
        data.put_str(&self.key_exchange.to_string());
        data.put_str(&self.public_key.to_string());
        data.put_str(&self.c_encryption.to_string());
        data.put_str(&self.s_encryption.to_string());
        data.put_str(&self.c_mac.to_string());
        data.put_str(&self.s_mac.to_string());
        data.put_str(&self.c_compress.to_string());
        data.put_str(&self.s_compress.to_string());
        data.to_vec()
    }
}

impl<'a> Packet<'a> for AlgList {
    fn pack(self, client: &'a mut Client) -> crate::model::SecPacket<'a> {
        info!("client algorithms: [{:?}]", self);
        let mut data = Data::new();
        data.put_u8(ssh_transport_code::KEXINIT);
        data.extend(util::cookie());
        data.extend(self.as_i());
        data.put_str("")
            .put_str("")
            .put_u8(false as u8)
            .put_u32(0_u32);

        (data, client).into()
    }

    fn unpack(pkt: SecPacket) -> SshResult<Self>
    where
        Self: Sized,
    {
        let data = pkt.into_inner();
        assert_eq!(data[0], ssh_transport_code::KEXINIT);
        AlgList::from(data)
    }
}
