use crate::{SshError, SshResult};
use std::time::{Duration, Instant};

#[cfg(not(target_arch = "wasm32"))]
const NANOS_PER_SEC: u64 = 1_000_000_000;

pub(crate) struct Timeout {
    instant: Instant,
    timeout: Option<Duration>,
    wait_tick: u64,
}

impl Timeout {
    pub fn new(timeout: Option<Duration>) -> Self {
        Timeout {
            instant: Instant::now(),
            timeout,
            wait_tick: 1,
        }
    }

    fn wait(&mut self) -> u64 {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let sleep_time = Duration::from_nanos(self.wait_tick);
            std::thread::sleep(sleep_time);
            if self.wait_tick < NANOS_PER_SEC {
                self.wait_tick <<= 1;
            }
        }
        self.wait_tick
    }

    pub fn till_next_tick(&mut self) -> SshResult<()> {
        if let Some(t) = self.timeout {
            if self.instant.elapsed() > t {
                tracing::error!("time out.");
                Err(SshError::TimeoutError)
            } else {
                self.wait();
                Ok(())
            }
        } else {
            self.wait();
            Ok(())
        }
    }

    pub fn renew(&mut self) {
        self.instant = Instant::now();
    }
}
