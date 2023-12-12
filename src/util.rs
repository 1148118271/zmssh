use crate::error::SshResult;
use rand::rngs::OsRng;
use rand::Rng;

#[cfg(feature = "scp")]
use crate::error::SshError;
#[cfg(feature = "scp")]
use std::{
    path::Path,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(feature = "scp")]
pub(crate) fn sys_time_to_secs(time: SystemTime) -> SshResult<u64> {
    Ok(time.duration_since(UNIX_EPOCH)?.as_secs())
}

// a random cookie
pub(crate) fn cookie() -> Vec<u8> {
    let cookie: [u8; 16] = OsRng.gen();
    cookie.to_vec()
}

pub(crate) fn vec_u8_to_string(v: Vec<u8>, pat: &str) -> SshResult<Vec<String>> {
    let result = String::from_utf8(v)?;
    let r: Vec<&str> = result.split(pat).collect();
    let mut vec = vec![];
    for x in r {
        vec.push(x.to_owned())
    }
    Ok(vec)
}

#[cfg(feature = "scp")]
pub(crate) fn check_path(path: &Path) -> SshResult<()> {
    if path.to_str().is_none() {
        return Err(SshError::InvalidScpFilePath);
    }
    Ok(())
}

#[cfg(feature = "scp")]
pub(crate) fn file_time(v: Vec<u8>) -> SshResult<(i64, i64)> {
    let mut t = vec![];
    for x in v {
        if x == b'T' || x == 32 || x == 10 {
            continue;
        }
        t.push(x)
    }
    let a = t.len() / 2;
    let ct = String::from_utf8(t[..(a - 1)].to_vec())?;
    let ut = String::from_utf8(t[a..(t.len() - 1)].to_vec())?;
    Ok((i64::from_str(&ct)?, i64::from_str(&ut)?))
}
