use std::ops::{Deref, DerefMut};

use crate::error::SshResult;

use super::Packet;

/// Data Type Representations Used in the SSH Protocols
/// <https://www.rfc-editor.org/rfc/rfc4251#section-5>

/// byte
///
/// A byte represents an arbitrary 8-bit value (octet).  Fixed length
/// data is sometimes represented as an array of bytes, written
/// byte[n], where n is the number of bytes in the array.
///
/// **boolean**
///
/// A boolean value is stored as a single byte.  The value 0
/// represents FALSE, and the value 1 represents TRUE.  All non-zero
/// values MUST be interpreted as TRUE; however, applications MUST NOT
/// store values other than 0 and 1.
///
/// **uint32**
///
/// Represents a 32-bit unsigned integer.  Stored as four bytes in the
/// order of decreasing significance (network byte order).  For
/// example: the value 699921578 (0x29b7f4aa) is stored as 29 b7 f4
/// aa.
///
/// **uint64**
///
/// Represents a 64-bit unsigned integer.  Stored as eight bytes in
/// the order of decreasing significance (network byte order).
///
/// **string**
///
/// Arbitrary length binary string.  Strings are allowed to contain
/// arbitrary binary data, including null characters and 8-bit
/// characters.  They are stored as a uint32 containing its length
/// (number of bytes that follow) and zero (= empty string) or more
/// bytes that are the value of the string.  Terminating null
/// characters are not used.
///
/// Strings are also used to store text.  In that case, US-ASCII is
/// used for internal names, and ISO-10646 UTF-8 for text that might
/// be displayed to the user.  The terminating null character SHOULD
/// NOT normally be stored in the string.  For example: the US-ASCII
/// string "testing" is represented as 00 00 00 07 t e s t i n g.  The
/// UTF-8 mapping does not alter the encoding of US-ASCII characters.
///
/// **mpint**
///
/// Represents multiple precision integers in two's complement format,
/// stored as a string, 8 bits per byte, MSB first.  Negative numbers
/// have the value 1 as the most significant bit of the first byte of
/// the data partition.  If the most significant bit would be set for
/// a positive number, the number MUST be preceded by a zero byte.
/// Unnecessary leading bytes with the value 0 or 255 MUST NOT be
/// included.  The value zero MUST be stored as a string with zero
/// bytes of data.
///
/// By convention, a number that is used in modular computations in
/// Z_n SHOULD be represented in the range 0 <= x < n.
///
///    Examples:
///
///    value (hex)        representation (hex)
///    -----------        --------------------
///    0                  00 00 00 00
///    9a378f9b2e332a7    00 00 00 08 09 a3 78 f9 b2 e3 32 a7
///    80                 00 00 00 02 00 80
///    -1234              00 00 00 02 ed cc
///    -deadbeef          00 00 00 05 ff 21 52 41 11
///
/// **name-list**
///
/// A string containing a comma-separated list of names.  A name-list
/// is represented as a uint32 containing its length (number of bytes
/// that follow) followed by a comma-separated list of zero or more
/// names.  A name MUST have a non-zero length, and it MUST NOT
/// contain a comma (",").  As this is a list of names, all of the
/// elements contained are names and MUST be in US-ASCII.  Context may
/// impose additional restrictions on the names.  For example, the
/// names in a name-list may have to be a list of valid algorithm
/// identifiers (see Section 6 below), or a list of [RFC3066] language
/// tags.  The order of the names in a name-list may or may not be
/// significant.  Again, this depends on the context in which the list
/// is used.  Terminating null characters MUST NOT be used, neither
/// for the individual names, nor for the list as a whole.
///
///  Examples:
///
///  value                      representation (hex)
///  -----                      --------------------
///  (), the empty name-list    00 00 00 00
///  ("zlib")                   00 00 00 04 7a 6c 69 62
///  ("zlib,none")              00 00 00 09 7a 6c 69 62 2c 6e 6f 6e 65

#[derive(Debug, Clone)]
pub(crate) struct Data(Vec<u8>);

impl Default for Data {
    fn default() -> Self {
        Self::new()
    }
}

impl Data {
    pub fn new() -> Data {
        Data(Vec::new())
    }

    #[allow(clippy::uninit_vec)]
    pub fn uninit_new(len: usize) -> Data {
        let mut v = Vec::with_capacity(len);
        unsafe { v.set_len(len) }
        Data(v)
    }

    // write uint8
    pub fn put_u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }

    // write uint32
    pub fn put_u32(&mut self, v: u32) -> &mut Self {
        let vec = v.to_be_bytes().to_vec();
        self.0.extend(&vec);
        self
    }

    // write string
    pub fn put_str(&mut self, str: &str) -> &mut Self {
        let v = str.as_bytes();
        self.put_u32(v.len() as u32);
        self.0.extend(v);
        self
    }

    // write [bytes]
    pub fn put_u8s(&mut self, v: &[u8]) -> &mut Self {
        self.put_u32(v.len() as u32);
        self.0.extend(v);
        self
    }

    // write mpint
    pub fn put_mpint(&mut self, v: &[u8]) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();
        // 0x80 = 128
        if v[0] & 0x80 != 0 {
            result.push(0);
        }
        result.extend(v);
        self.put_u8s(&result).to_vec()
    }

    // skip `size`
    pub fn skip(&mut self, size: usize) {
        self.0.drain(..size);
    }

    // get uint8
    pub fn get_u8(&mut self) -> u8 {
        self.0.remove(0)
    }

    // get uint32
    pub fn get_u32(&mut self) -> u32 {
        let u32_buf = self.0.drain(..4).collect::<Vec<u8>>();
        u32::from_be_bytes(u32_buf.try_into().unwrap())
    }

    // get [bytes]
    pub fn get_u8s(&mut self) -> Vec<u8> {
        let len = self.get_u32() as usize;
        let bytes = self.0.drain(..len).collect::<Vec<u8>>();
        bytes
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for Data {
    fn from(v: Vec<u8>) -> Self {
        Data(v)
    }
}

impl From<&[u8]> for Data {
    fn from(v: &[u8]) -> Self {
        Data(v.into())
    }
}

impl From<Data> for Vec<u8> {
    fn from(data: Data) -> Self {
        data.0
    }
}

impl Deref for Data {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Data {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a> Packet<'a> for Data {
    fn pack(self, client: &'a mut crate::client::Client) -> super::packet::SecPacket<'a> {
        (self, client).into()
    }
    fn unpack(pkt: super::packet::SecPacket) -> SshResult<Self>
    where
        Self: Sized,
    {
        Ok(pkt.into_inner())
    }
}
