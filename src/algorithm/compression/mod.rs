use super::Compress;
use crate::SshResult;

mod zlib;
/// <https://www.rfc-editor.org/rfc/rfc4253#section-6.2>
pub(crate) trait Compression: Send + Sync {
    fn new() -> Self
    where
        Self: Sized;
    // The "zlib@openssh.com" method operates identically to the "zlib"
    // method described in [RFC4252] except that packet compression does not
    // start until the server sends a SSH_MSG_USERAUTH_SUCCESS packet
    // so
    // fn start();
    fn compress(&mut self, buf: &[u8]) -> SshResult<Vec<u8>>;
    fn decompress(&mut self, buf: &[u8]) -> SshResult<Vec<u8>>;
}

pub(crate) fn from(comp: &Compress) -> Box<dyn Compression> {
    match comp {
        Compress::None => Box::new(CompressNone::new()),
        #[cfg(feature = "deprecated-zlib")]
        Compress::Zlib => Box::new(zlib::CompressZlib::new()),
        Compress::ZlibOpenSsh => Box::new(zlib::CompressZlib::new()),
    }
}

#[derive(Default)]
pub(crate) struct CompressNone {}

impl Compression for CompressNone {
    fn new() -> Self {
        Self {}
    }

    fn compress(&mut self, buf: &[u8]) -> SshResult<Vec<u8>> {
        Ok(buf.to_vec())
    }

    fn decompress(&mut self, buf: &[u8]) -> SshResult<Vec<u8>> {
        Ok(buf.to_vec())
    }
}
