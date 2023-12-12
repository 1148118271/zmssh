use crate::constant::size::LOCAL_WINDOW_SIZE;

use crate::constant::size;

pub(crate) struct FlowControl {
    local_window: u32,
    remote_window: u32,
}

impl FlowControl {
    pub fn new(remote: u32) -> Self {
        FlowControl {
            local_window: LOCAL_WINDOW_SIZE,
            remote_window: remote,
        }
    }

    pub fn tune_on_recv(&mut self, buf: &mut Vec<u8>) {
        let recv_len = buf.len() as u32;

        if self.local_window >= recv_len {
            self.local_window -= recv_len;
        } else {
            let drop_len = recv_len - self.local_window;
            tracing::debug!("Recv more than expected, drop len {}", drop_len);
            buf.truncate(self.local_window as usize);
            self.local_window = 0;
        }
    }

    pub fn tune_on_send(&mut self, buf: &mut Vec<u8>) -> Vec<u8> {
        let want_send = buf.len();

        let can_send = {
            let mut can_send = want_send;

            if can_send > self.remote_window as usize {
                can_send = self.remote_window as usize
            }

            if can_send > size::BUF_SIZE {
                can_send = size::BUF_SIZE
            }
            can_send
        };

        self.remote_window -= can_send as u32;

        buf.split_off(can_send)
    }

    pub fn on_recv(&mut self, size: u32) {
        self.remote_window += size
    }

    pub fn on_send(&mut self, size: u32) {
        self.local_window += size
    }

    pub fn can_send(&self) -> bool {
        self.remote_window > 0
    }
}
