/// The client version
pub(crate) const CLIENT_VERSION: &str = "SSH-2.0-SSH_RS-0.4.5";
pub(crate) const SSH_MAGIC: &[u8] = b"SSH-";

/// The constant strings that used for ssh communication
#[allow(dead_code)]
pub(crate) mod ssh_str {
    /// Pre-auth msg
    pub const SSH_USERAUTH: &str = "ssh-userauth";
    /// Authenticate msg
    pub const SSH_CONNECTION: &str = "ssh-connection";
    /// Authenticate with public key
    pub const PUBLIC_KEY: &str = "publickey";
    /// Authenticate with password
    pub const PASSWORD: &str = "password";
    /// Session level msg
    pub const SESSION: &str = "session";
    /// Open a Shell
    pub const SHELL: &str = "shell";
    /// Execute a command
    pub const EXEC: &str = "exec";
    /// SCP
    pub const SCP: &str = "scp";
    /// Request a pesudo-terminal
    pub const PTY_REQ: &str = "pty-req";
    /// The xterm style that used for the pty
    pub const XTERM_VAR: &str = "xterm-256color";
}

#[allow(dead_code)]
pub(crate) mod permission {
    /// The default permission for directories
    pub const DIR: &str = "775";
    /// The default permission for files
    pub const FILE: &str = "664";
}

/// Some constants that used when scp
#[cfg(feature = "scp")]
#[allow(dead_code)]
pub(crate) mod scp {
    /// Scp from our to the remote
    pub const SOURCE: &str = "-f";
    /// Scp from the remote to our
    pub const SINK: &str = "-t";
    /// Recursive scp for a dir
    pub const RECURSIVE: &str = "-r";
    /// Show details
    pub const VERBOSE: &str = "-v";
    /// Keep the modification, access time and permission the same with the origin
    pub const PRESERVE_TIMES: &str = "-p";
    /// Show not progress bar
    pub const QUIET: &str = "-q";
    /// Limit the bandwidth usage
    pub const LIMIT: &str = "-l";

    /// Indicate the modification, access time of the file we recieve
    /// "T1647767946 0 1647767946 0\n";
    pub const T: u8 = b'T';
    /// Indicate that we are recieving a directory
    /// "D0775 0 dirName\n"
    pub const D: u8 = b'D';
    /// Indicate that we are recieving a file
    /// "C0664 200 fileName.js\n"
    pub const C: u8 = b'C';
    /// Indicate that current directory is done
    /// "D\n"
    pub const E: u8 = b'E';

    /// The end flag of current operation
    // '\0'
    pub const END: u8 = 0;
    /// Exceptions occur
    pub const ERR: u8 = 1;
    /// Exceptions that cannot recover
    pub const FATAL_ERR: u8 = 2;
}

#[allow(dead_code)]
pub(crate) mod size {
    pub const FILE_CHUNK: usize = 30000;
    /// The max size of one packet
    pub const BUF_SIZE: usize = 32768;
    /// The default window size of the flow-control
    pub const LOCAL_WINDOW_SIZE: u32 = 2097152;
}

/// <https://www.rfc-editor.org/rfc/rfc4254#section-9>
#[allow(dead_code)]
pub(crate) mod ssh_connection_code {
    pub const GLOBAL_REQUEST: u8 = 80;
    pub const REQUEST_SUCCESS: u8 = 81;
    pub const REQUEST_FAILURE: u8 = 82;
    pub const CHANNEL_OPEN: u8 = 90;
    pub const CHANNEL_OPEN_CONFIRMATION: u8 = 91;
    pub const CHANNEL_OPEN_FAILURE: u8 = 92;
    pub const CHANNEL_WINDOW_ADJUST: u8 = 93;
    pub const CHANNEL_DATA: u8 = 94;
    pub const CHANNEL_EXTENDED_DATA: u8 = 95;
    pub const CHANNEL_EOF: u8 = 96;
    pub const CHANNEL_CLOSE: u8 = 97;
    pub const CHANNEL_REQUEST: u8 = 98;
    pub const CHANNEL_SUCCESS: u8 = 99;
    pub const CHANNEL_FAILURE: u8 = 100;
}

/// <https://www.rfc-editor.org/rfc/rfc4254#section-5.1>
#[allow(dead_code)]
pub(crate) mod ssh_channel_fail_code {
    pub const ADMINISTRATIVELY_PROHIBITED: u32 = 1;
    pub const CONNECT_FAILED: u32 = 2;
    pub const UNKNOWN_CHANNEL_TYPE: u32 = 3;
    pub const RESOURCE_SHORTAGE: u32 = 4;
}

/// <https://www.rfc-editor.org/rfc/rfc4253#section-12>
#[allow(dead_code)]
pub(crate) mod ssh_transport_code {
    pub const DISCONNECT: u8 = 1;
    pub const IGNORE: u8 = 2;
    pub const UNIMPLEMENTED: u8 = 3;
    pub const DEBUG: u8 = 4;
    pub const SERVICE_REQUEST: u8 = 5;
    pub const SERVICE_ACCEPT: u8 = 6;
    pub const KEXINIT: u8 = 20;
    pub const NEWKEYS: u8 = 21;
    pub const KEXDH_INIT: u8 = 30;
    pub const KEXDH_REPLY: u8 = 31;
}

/// <https://www.rfc-editor.org/rfc/rfc4253#section-11.1>
#[allow(dead_code)]
pub(crate) mod ssh_disconnection_code {
    pub const HOST_NOT_ALLOWED_TO_CONNECT: u8 = 1;
    pub const PROTOCOL_ERROR: u8 = 2;
    pub const KEY_EXCHANGE_FAILED: u8 = 3;
    pub const RESERVED: u8 = 4;
    pub const MAC_ERROR: u8 = 5;
    pub const COMPRESSION_ERROR: u8 = 6;
    pub const SERVICE_NOT_AVAILABLE: u8 = 7;
    pub const PROTOCOL_VERSION_NOT_SUPPORTED: u8 = 8;
    pub const HOST_KEY_NOT_VERIFIABLE: u8 = 9;
    pub const CONNECTION_LOST: u8 = 10;
    pub const BY_APPLICATION: u8 = 11;
    pub const TOO_MANY_CONNECTIONS: u8 = 12;
    pub const AUTH_CANCELLED_BY_USER: u8 = 13;
    pub const NO_MORE_AUTH_METHODS_AVAILABLE: u8 = 14;
    pub const ILLEGAL_USER_NAME: u8 = 15;
}

/// <https://www.rfc-editor.org/rfc/rfc4252#section-6>
#[allow(dead_code)]
pub(crate) mod ssh_user_auth_code {
    pub const REQUEST: u8 = 50;
    pub const FAILURE: u8 = 51;
    pub const SUCCESS: u8 = 52;
    pub const BANNER: u8 = 53;
    pub const PK_OK: u8 = 60;
}

/// The magic that used when doing hash after kex
pub(crate) const ALPHABET: [u8; 6] = [b'A', b'B', b'C', b'D', b'E', b'F'];
