use std::io::{Read, Write};
use std::time::Duration;

use crate::error::SshResult;
use crate::{client::Client, model::Data};

use super::timeout::Timeout;

/// ## Binary Packet Protocol
///
/// <https://www.rfc-editor.org/rfc/rfc4253#section-6>
///
/// uint32 `packet_length`
///
/// byte `padding_length`
///
/// byte[[n1]] `payload`; n1 = packet_length - padding_length - 1
///
/// byte[[n2]] `random padding`; n2 = padding_length
///
/// byte[[m]] `mac` (Message Authentication Code - MAC); m = mac_length
///
/// ---
///
/// **packet_length**
/// The length of the packet in bytes, not including 'mac' or the 'packet_length' field itself.
///
///
/// **padding_length**
/// Length of 'random padding' (bytes).
///
///
/// **payload**
///  The useful contents of the packet.  If compression has been negotiated, this field is compressed.
/// Initially, compression MUST be "none".
///
///
/// **random padding**
/// Arbitrary-length padding, such that the total length of
/// (packet_length || padding_length || payload || random padding)
/// is a multiple of the cipher block size or 8, whichever is
/// larger.  There MUST be at least four bytes of padding.  The
/// padding SHOULD consist of random bytes.  The maximum amount of
/// padding is 255 bytes.

///
/// **mac**
/// Message Authentication Code.  If message authentication has
/// been negotiated, this field contains the MAC bytes.  Initially,
/// the MAC algorithm MUST be "none".。

fn read_with_timeout<S>(stream: &mut S, tm: Option<Duration>, buf: &mut [u8]) -> SshResult<()>
where
    S: Read,
{
    let want_len = buf.len();
    let mut offset = 0;
    let mut timeout = Timeout::new(tm);

    loop {
        match stream.read(&mut buf[offset..]) {
            Ok(i) => {
                offset += i;
                if offset == want_len {
                    return Ok(());
                } else {
                    timeout.renew();
                    continue;
                }
            }
            Err(e) => {
                if let std::io::ErrorKind::WouldBlock = e.kind() {
                    timeout.till_next_tick()?;
                    continue;
                } else {
                    return Err(e.into());
                }
            }
        };
    }
}

fn try_read<S>(stream: &mut S, _tm: Option<Duration>, buf: &mut [u8]) -> SshResult<usize>
where
    S: Read,
{
    match stream.read(buf) {
        Ok(i) => Ok(i),
        Err(e) => {
            if let std::io::ErrorKind::WouldBlock = e.kind() {
                Ok(0)
            } else {
                Err(e.into())
            }
        }
    }
}

fn write_with_timeout<S>(stream: &mut S, tm: Option<Duration>, buf: &[u8]) -> SshResult<()>
where
    S: Write,
{
    let want_len = buf.len();
    let mut offset = 0;
    let mut timeout = Timeout::new(tm);

    loop {
        match stream.write(&buf[offset..]) {
            Ok(i) => {
                offset += i;
                if offset == want_len {
                    return Ok(());
                } else {
                    timeout.renew();
                    continue;
                }
            }
            Err(e) => {
                if let std::io::ErrorKind::WouldBlock = e.kind() {
                    timeout.till_next_tick()?;
                    continue;
                } else {
                    return Err(e.into());
                }
            }
        };
    }
}

pub(crate) trait Packet<'a> {
    fn pack(self, client: &'a mut Client) -> SecPacket<'a>;
    fn unpack(pkt: SecPacket) -> SshResult<Self>
    where
        Self: Sized;
}

pub(crate) struct SecPacket<'a> {
    payload: Data,
    client: &'a mut Client,
}

impl<'a> SecPacket<'a> {
    fn get_align(bsize: usize) -> i32 {
        let bsize = bsize as i32;
        if bsize > 8 {
            bsize
        } else {
            8
        }
    }

    pub fn write_stream<S>(self, stream: &mut S) -> SshResult<()>
    where
        S: Write,
    {
        let tm = self.client.get_timeout();
        let payload = self.client.get_compressor().compress(&self.payload)?;
        let payload_len = payload.len() as u32;
        let pad_len = {
            let mut pad = payload_len as i32 + 1;
            let block_size = Self::get_align(self.client.get_encryptor().bsize());
            if !self.client.get_encryptor().no_pad() {
                pad += 4
            }
            (((-pad) & (block_size - 1)) + block_size) as u32
        } as u8;
        let packet_len = 1 + pad_len as u32 + payload_len;
        let mut buf = vec![];
        buf.extend(packet_len.to_be_bytes());
        buf.extend([pad_len]);
        buf.extend(payload);
        buf.extend(vec![0; pad_len as usize]);
        let seq = self.client.get_seq().get_client();
        self.client.get_encryptor().encrypt(seq, &mut buf);
        write_with_timeout(stream, tm, &buf)
    }

    pub fn from_stream<S>(stream: &mut S, client: &'a mut Client) -> SshResult<Self>
    where
        S: Read,
    {
        let tm = client.get_timeout();
        let bsize = Self::get_align(client.get_encryptor().bsize()) as usize;

        // read the first block
        let mut first_block = vec![0; bsize];
        read_with_timeout(stream, tm, &mut first_block)?;

        // detect the total len
        let seq = client.get_seq().get_server();
        let data_len = client.get_encryptor().data_len(seq, &first_block);

        // read remain
        let mut data = Data::uninit_new(data_len);
        data[0..bsize].clone_from_slice(&first_block);
        read_with_timeout(stream, tm, &mut data[bsize..])?;

        // decrypt all
        let data = client.get_encryptor().decrypt(seq, &mut data)?;

        // unpacking
        let pkt_len = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let pad_len = data[4];
        let payload_len = pkt_len - pad_len as u32 - 1;

        let payload = data[5..payload_len as usize + 5].into();
        let payload = client.get_compressor().decompress(payload)?.into();

        Ok(Self { payload, client })
    }

    pub fn try_from_stream<S>(stream: &mut S, client: &'a mut Client) -> SshResult<Option<Self>>
    where
        S: Read,
    {
        let tm = client.get_timeout();
        let bsize = Self::get_align(client.get_encryptor().bsize()) as usize;

        // read the first block
        let mut first_block = vec![0; bsize];
        let read = try_read(stream, tm, &mut first_block)?;
        if read == 0 {
            return Ok(None);
        }

        // detect the total len
        let seq = client.get_seq().get_server();
        let data_len = client.get_encryptor().data_len(seq, &first_block);

        // read remain
        let mut data = Data::uninit_new(data_len);
        data[0..bsize].clone_from_slice(&first_block);
        read_with_timeout(stream, tm, &mut data[bsize..])?;

        // decrypt all
        let data = client.get_encryptor().decrypt(seq, &mut data)?;

        // unpacking
        let pkt_len = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let pad_len = data[4];
        let payload_len = pkt_len - pad_len as u32 - 1;

        let payload = data[5..payload_len as usize + 5].into();

        Ok(Some(Self { payload, client }))
    }

    pub fn get_inner(&self) -> &[u8] {
        &self.payload
    }

    pub fn into_inner(self) -> Data {
        self.payload
    }
}

impl<'a> From<(Data, &'a mut Client)> for SecPacket<'a> {
    fn from((d, c): (Data, &'a mut Client)) -> Self {
        Self {
            payload: d,
            client: c,
        }
    }
}
