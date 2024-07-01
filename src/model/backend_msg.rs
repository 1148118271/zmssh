use std::sync::mpsc::Sender;

use super::Data;

pub(crate) enum BackendRqst {
    OpenChannel(u32, Data, Sender<BackendResp>),
    Data(u32, Data),
    Command(u32, Data),
    CloseChannel(u32, Data),
}

pub(crate) enum BackendResp {
    Ok(u32),
    Fail(String),
    Data(Data),
    ExitStatus(u32),
    TermMsg(String),
    Close,
}
