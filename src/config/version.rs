use std::io::{Read, Write};
use std::time::Duration;
use tracing::*;

use crate::{
    constant::{self, CLIENT_VERSION, SSH_MAGIC},
    error::{SshError, SshResult},
    model::Timeout,
};

#[derive(Debug, Clone)]
pub(crate) struct SshVersion {
    pub client_ver: String,
    pub server_ver: String,
}

impl Default for SshVersion {
    fn default() -> Self {
        Self {
            client_ver: CLIENT_VERSION.to_owned(),
            server_ver: String::new(),
        }
    }
}

/// <https://www.rfc-editor.org/rfc/rfc4253#section-4.2>

// When the connection has been established, both sides MUST send an
// identification string.  This identification string MUST be

//    SSH-protoversion-softwareversion SP comments CR LF

// Since the protocol being defined in this set of documents is version
// 2.0, the 'protoversion' MUST be "2.0".  The 'comments' string is
// OPTIONAL.  If the 'comments' string is included, a 'space' character
// (denoted above as SP, ASCII 32) MUST separate the 'softwareversion'
// and 'comments' strings.  The identification MUST be terminated by a
// single Carriage Return (CR) and a single Line Feed (LF) character
// (ASCII 13 and 10, respectively).
fn read_version<S>(stream: &mut S, tm: Option<Duration>) -> SshResult<Vec<u8>>
where
    S: Read,
{
    let mut ch = vec![0; 1];
    const LF: u8 = 0xa;
    let crlf = vec![0xd, 0xa];
    let mut outbuf = vec![];
    let mut timeout = Timeout::new(tm);
    loop {
        match stream.read(&mut ch) {
            Ok(i) => {
                if 0 == i {
                    // eof got, return
                    return Ok(outbuf);
                }

                outbuf.extend_from_slice(&ch);

                if LF == ch[0] && outbuf.len() > 1 && outbuf.ends_with(&crlf) {
                    // The server MAY send other lines of data before sending the version
                    // string.  Each line SHOULD be terminated by a Carriage Return and Line
                    // Feed.  Such lines MUST NOT begin with "SSH-", and SHOULD be encoded
                    // in ISO-10646 UTF-8 [RFC3629] (language is not specified).  Clients
                    // MUST be able to process such lines.  Such lines MAY be silently
                    // ignored, or MAY be displayed to the client user.
                    if outbuf.len() < 4 || &outbuf[0..4] != SSH_MAGIC {
                        // skip other lines
                        // and start read for another line
                        outbuf.clear();
                        continue;
                    }
                    return Ok(outbuf);
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

impl SshVersion {
    pub fn read_server_version<S>(
        &mut self,
        stream: &mut S,
        timeout: Option<Duration>,
    ) -> SshResult<()>
    where
        S: Read,
    {
        let buf = read_version(stream, timeout)?;
        if buf.len() < 4 || &buf[0..4] != SSH_MAGIC {
            error!("SSH version magic doesn't match");
            error!("Probably not an ssh server");
        }
        let from_utf8 = String::from_utf8(buf)?;
        let version_str = from_utf8.trim();
        info!("server version: [{}]", version_str);

        self.server_ver = version_str.to_owned();
        Ok(())
    }

    pub fn send_our_version<S>(&self, stream: &mut S) -> SshResult<()>
    where
        S: Write,
    {
        info!("client version: [{}]", self.client_ver);
        let ver_string = format!("{}\r\n", self.client_ver);
        let _ = stream.write(ver_string.as_bytes())?;
        Ok(())
    }

    pub fn validate(&self) -> SshResult<()> {
        if self.server_ver.contains("SSH-2.0") {
            Ok(())
        } else {
            error!("error in version negotiation, version mismatch.");
            Err(SshError::VersionDismatchError {
                our: constant::CLIENT_VERSION.to_owned(),
                their: self.server_ver.clone(),
            })
        }
    }
}
