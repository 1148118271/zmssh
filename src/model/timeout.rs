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

            if let Some(timemout) = self.timeout {
                let timeout_nanos = timemout.as_nanos();
                let used_nanos = self.instant.elapsed().as_nanos();

                self.wait_tick = {
                    if timeout_nanos > used_nanos
                        && timeout_nanos - used_nanos < self.wait_tick as u128
                    {
                        (timeout_nanos - used_nanos) as u64
                    } else {
                        self.wait_tick
                    }
                };
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
        self.wait_tick = 1
    }
}
