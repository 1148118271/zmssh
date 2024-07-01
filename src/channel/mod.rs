mod backend;
mod local;

pub(crate) use backend::Channel as BackendChannel;
pub use backend::{ChannelBroker, ExecBroker, ShellBrocker};

pub use local::Channel as LocalChannel;
pub use local::ChannelExec as LocalExec;
pub use local::ChannelShell as LocalShell;

#[cfg(feature = "scp")]
pub use backend::ScpBroker;
#[cfg(feature = "scp")]
pub use local::ChannelScp as LocalScp;
