use std::{
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

/// Unix-seconds clock with an injectable offset so tests can exercise expiry
/// policies (sessions, bootstrap tokens, login throttling, renewals) without
/// real waiting. Production always uses `Clock::system()` with a zero offset.
#[derive(Clone, Debug, Default)]
pub struct Clock {
    offset: Arc<AtomicI64>,
}

impl Clock {
    pub fn system() -> Self {
        Self::default()
    }

    pub fn now(&self) -> i64 {
        let system = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after Unix epoch")
            .as_secs() as i64;
        system + self.offset.load(Ordering::Relaxed)
    }

    /// Advance every reader of this clock by `seconds`. Test-only in spirit,
    /// but harmless in production (nothing calls it there).
    pub fn advance(&self, seconds: i64) {
        self.offset.fetch_add(seconds, Ordering::Relaxed);
    }
}
