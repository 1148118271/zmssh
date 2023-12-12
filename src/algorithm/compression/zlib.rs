use flate2;

use crate::SshError;

use super::Compression;

/// The "zlib" compression is described in [RFC1950] and in [RFC1951].
/// The compression context is initialized after each key exchange, and
/// is passed from one packet to the next, with only a partial flush
/// being performed at the end of each packet.  A partial flush means
/// that the current compressed block is ended and all data will be
/// output.  If the current block is not a stored block, one or more
/// empty blocks are added after the current block to ensure that there
/// are at least 8 bits, counting from the start of the end-of-block code
/// of the current block to the end of the packet payload.
///
/// <https://www.openssh.com/txt/draft-miller-secsh-compression-delayed-00.txt>
/// The "zlib@openssh.com" method operates identically to the "zlib"
/// method described in [RFC4252] except that packet compression does not
/// start until the server sends a SSH_MSG_USERAUTH_SUCCESS packet,
/// replacing the "zlib" method's start of compression when the server
/// sends SSH_MSG_NEWKEYS.
pub(super) struct CompressZlib {
    decompressor: flate2::Decompress,
    compressor: flate2::Compress,
}

impl Compression for CompressZlib {
    fn new() -> Self
    where
        Self: Sized,
    {
        Self {
            decompressor: flate2::Decompress::new(true),
            compressor: flate2::Compress::new(flate2::Compression::fast(), true),
        }
    }

    fn decompress(&mut self, buf: &[u8]) -> crate::SshResult<Vec<u8>> {
        let mut buf_in = buf;
        let mut buf_once = [0; 4096];
        let mut buf_out = vec![];
        loop {
            let in_before = self.decompressor.total_in();
            let out_before = self.decompressor.total_out();

            let result =
                self.decompressor
                    .decompress(buf_in, &mut buf_once, flate2::FlushDecompress::Sync);

            let consumed = (self.decompressor.total_in() - in_before) as usize;
            let produced = (self.decompressor.total_out() - out_before) as usize;

            match result {
                Ok(flate2::Status::Ok) => {
                    buf_in = &buf_in[consumed..];
                    buf_out.extend(&buf_once[..produced]);
                }
                Ok(flate2::Status::StreamEnd) => {
                    return Err(SshError::CompressionError(
                        "Stream ends during the decompress".to_owned(),
                    ));
                }
                Ok(flate2::Status::BufError) => {
                    break;
                }
                Err(e) => return Err(SshError::CompressionError(e.to_string())),
            }
        }

        Ok(buf_out)
    }

    fn compress(&mut self, buf: &[u8]) -> crate::SshResult<Vec<u8>> {
        let mut buf_in = buf;
        let mut buf_once = [0; 4096];
        let mut buf_out = vec![];
        loop {
            let in_before = self.compressor.total_in();
            let out_before = self.compressor.total_out();

            let result =
                self.compressor
                    .compress(buf_in, &mut buf_once, flate2::FlushCompress::Partial);

            let consumed = (self.compressor.total_in() - in_before) as usize;
            let produced = (self.compressor.total_out() - out_before) as usize;

            // tracing::info!(consumed);
            // tracing::info!(produced);

            // means an empty compress
            // 2 bytes ZLIB header at the start of the stream
            // 4 bytes CRC checksum at the end of the stream
            if produced == 6 {
                break;
            }

            match result {
                Ok(flate2::Status::Ok) => {
                    buf_in = &buf_in[consumed..];
                    buf_out.extend(&buf_once[..produced]);
                }
                Ok(flate2::Status::StreamEnd) => {
                    return Err(SshError::CompressionError(
                        "Stream ends during the compress".to_owned(),
                    ));
                }
                Ok(flate2::Status::BufError) => {
                    break;
                }
                Err(e) => return Err(SshError::CompressionError(e.to_string())),
            }
        }

        Ok(buf_out)
    }
}
