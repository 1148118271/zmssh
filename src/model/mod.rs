mod backend_msg;
mod data;
mod flow_control;
mod packet;
mod sequence;
mod terminal;
mod timeout;
mod u32iter;

#[cfg(feature = "scp")]
mod scp_file;

use std::{
    cell::RefCell,
    rc::Rc,
    sync::{Arc, Mutex},
};

pub use terminal::*;

pub(crate) use backend_msg::*;
pub(crate) use data::Data;
pub(crate) use flow_control::FlowControl;
pub(crate) use packet::{Packet, SecPacket};
pub(crate) use sequence::Sequence;
pub(crate) use timeout::Timeout;
pub(crate) use u32iter::U32Iter;

#[cfg(feature = "scp")]
pub(crate) use scp_file::ScpFile;

pub(crate) type RcMut<T> = Rc<RefCell<T>>;
pub(crate) type ArcMut<T> = Arc<Mutex<T>>;
