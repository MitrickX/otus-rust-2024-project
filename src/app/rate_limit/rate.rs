use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub enum Rate {
    PerSecond(u64),
    PerMinute(u64),
    PerHour(u64),
}

impl Rate {
    /// Returns the rate limit value.
    ///
    /// # Returns
    ///
    /// * The rate limit value.
    pub fn limit(&self) -> u64 {
        match self {
            Rate::PerSecond(v) => *v,
            Rate::PerMinute(v) => *v,
            Rate::PerHour(v) => *v,
        }
    }

    /// Returns the time duration for the rate limit.
    ///
    /// # Returns
    ///
    /// * The time duration for the rate limit.
    pub fn duration(&self) -> Duration {
        match self {
            Rate::PerSecond(_) => Duration::from_secs(1),
            Rate::PerMinute(_) => Duration::from_secs(60),
            Rate::PerHour(_) => Duration::from_secs(3600),
        }
    }
}
