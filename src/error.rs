use std::sync::mpsc::{RecvError, SendError};

use thiserror::Error;

pub type SshResult<I> = Result<I, SshError>;

#[non_exhaustive]
#[derive(Debug, Error)]
pub enum SshError {
    #[error("Version dismatch: {our} vs {their}")]
    VersionDismatchError { our: String, their: String },
    #[error("Key exchange error: {0}")]
    KexError(String),
    #[error("Parse ssh key error: {0}")]
    SshPubKeyError(String),
    #[error("Auth error")]
    AuthError,
    #[error("Timeout")]
    TimeoutError,
    #[error(transparent)]
    DataFormatError(#[from] std::string::FromUtf8Error),
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    #[error("Compression error: {0}")]
    CompressionError(String),
    #[cfg(feature = "scp")]
    #[error(transparent)]
    SystemTimeError(#[from] std::time::SystemTimeError),
    #[cfg(feature = "scp")]
    #[error(transparent)]
    ParseIntError(#[from] std::num::ParseIntError),
    #[cfg(feature = "scp")]
    #[error("Invalid scp file path")]
    InvalidScpFilePath,
    #[cfg(feature = "scp")]
    #[error("Scp error: {0}")]
    ScpError(String),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error("IPC error: {0}")]
    IpcError(String),
    #[error("Ssh Error: {0}")]
    GeneralError(String),
}

impl From<RecvError> for SshError {
    fn from(value: RecvError) -> Self {
        Self::IpcError(value.to_string())
    }
}

impl<T> From<SendError<T>> for SshError {
    fn from(value: SendError<T>) -> Self {
        Self::IpcError(value.to_string())
    }
}
