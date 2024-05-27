#![allow(dead_code)]

use super::rate::Rate;
use std::{
    cmp::min,
    time::{Duration, SystemTime},
};

// Bucket trait is abstraction that implements aglothm https://en.wikipedia.org/wiki/Token_bucket

#[derive(Debug)]
pub(super) struct Bucket {
    // current count of tokens in bucket
    count: u64,

    // max possible count of tokens in bucket
    limit: u64,

    // duration of releasing one token
    duration: Duration,

    // last time when any token was conformed
    last_conformed: SystemTime,

    // last time activity of bucket (conformed or struct created)
    last_active: SystemTime,

    // max duration from last_active to current time that could signal that bucket already is not active
    activity_duration: Duration,
}

impl Bucket {
    /// Create new [`Bucket`]`
    ///
    /// # Arguments
    ///
    /// * `rate` - max count of tokens in bucket per period, for example Rate::PerMinute(10) means 10 tokens per minute
    pub fn new(rate: Rate) -> Self {
        let active_duration = rate.duration() * 2;
        Self::new_bucket(SystemTime::now(), rate, active_duration)
    }

    // private constructor for tests
    fn new_bucket(current_time: SystemTime, rate: Rate, active_duration: Duration) -> Self {
        let limit = rate.limit();
        let duration = Duration::from_nanos(rate.duration().as_nanos() as u64 / limit);

        Self {
            count: limit,
            limit,
            duration,
            last_conformed: SystemTime::UNIX_EPOCH,
            last_active: current_time,
            activity_duration: active_duration,
        }
    }

    /// Checks if packet conform backet
    ///
    /// # Returns
    ///
    /// * `true` - if packet conform
    /// * `false` - if packet not conform
    pub fn is_conformed(&mut self, current_time: SystemTime) -> bool {
        self.release_tokens(current_time);

        self.last_active = current_time;

        // in backet there as some tokens, which means that packet is conformed, so consume one token and return true
        if self.count > 0 {
            self.count -= 1;
            self.last_conformed = current_time;

            return true;
        }

        false
    }

    /// Check if backet still active
    ///
    /// # Returns
    ///
    /// * `true` - if backet still active
    /// * `false` - if backet not active
    fn is_active(&mut self, current_time: SystemTime) -> bool {
        // we must release tokens because since last IsConform could be pass enough time to full bucket
        self.release_tokens(current_time);

        // bucket is active yet when bucket is not full
        if self.count < self.limit {
            return true;
        }

        let elapsed = match current_time.duration_since(self.last_active) {
            Ok(elapsed) => elapsed,
            Err(_) => Duration::new(0, 0),
        };

        // bucket is not active when it is full to this time and wasn't be active for a while
        elapsed <= self.activity_duration
    }

    // release_tokens release tokens in bucket to this time
    fn release_tokens(&mut self, current_time: SystemTime) {
        let elapsed = match current_time.duration_since(self.last_conformed) {
            Ok(elapsed) => elapsed,
            Err(_) => Duration::new(0, 0),
        };

        let released_count = (elapsed.as_nanos() / self.duration.as_nanos()) as u64;
        self.count = min(self.count + released_count, self.limit);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_first_bucket_is_conformed() {
        let current_time = SystemTime::now();
        let mut bucket =
            Bucket::new_bucket(current_time, Rate::PerMinute(10), Duration::from_secs(60));
        assert!(bucket.is_conformed(current_time));
    }

    #[test]
    fn test_n_plus_one_not_conformed() {
        let current_time = SystemTime::now();
        let mut bucket =
            Bucket::new_bucket(current_time, Rate::PerMinute(5), Duration::from_secs(60));

        assert!(bucket.is_conformed(current_time));
        assert!(bucket.is_conformed(current_time + Duration::from_millis(50)));
        assert!(bucket.is_conformed(current_time + Duration::from_millis(250)));
        assert!(bucket.is_conformed(current_time + Duration::from_millis(1000)));
        assert!(bucket.is_conformed(current_time + Duration::from_millis(2500)));
        assert!(!bucket.is_conformed(current_time + Duration::from_millis(10000)));
    }

    #[test]
    fn test_conformation_after_enough_timeout() {
        let current_time = SystemTime::now();

        let n = 10;
        let mut bucket =
            Bucket::new_bucket(current_time, Rate::PerMinute(n), Duration::from_secs(60));

        for _ in 0..n {
            assert!(bucket.is_conformed(current_time));
        }

        let timeout_secs = Duration::from_secs(6); // 6 sec is enough timeout for current bucket release one token
        let next_check_time = current_time + timeout_secs;

        assert!(bucket.is_conformed(next_check_time));
    }

    #[test]
    fn test_token_release() {
        let current_time = SystemTime::now();
        let n = 10;
        let mut bucket =
            Bucket::new_bucket(current_time, Rate::PerMinute(n), Duration::from_secs(60));

        // Arrival of packets is one token in minute (slow for this limit rate)
        // So after each arrival we has 9 tokens left, cause on next conform enough tokens will released
        // Bucket always has plenty of tokens

        let mut time = current_time;
        for _ in 0..n {
            time += Duration::from_secs(60);
            assert!(bucket.is_conformed(time));

            assert_eq!(
                n - 1,
                bucket.count,
                "tokens in bucket must be plenty cause of slow arrival rates"
            );
        }
    }

    #[test]
    fn test_is_inactive_when_is_conformed_not_called() {
        let current_time = SystemTime::now();
        let active_duration = Duration::from_secs(60);
        let mut bucket = Bucket::new_bucket(current_time, Rate::PerMinute(10), active_duration);

        assert!(
            bucket.is_active(current_time),
            "bucket must be active right away after construction"
        );

        assert!(
            !bucket.is_active(current_time + active_duration + Duration::from_millis(1)),
            "bucket must be not active after wait timeout after constructor"
        );
    }

    #[test]
    fn test_is_active_right_after_is_conformed_called() {
        let current_time = SystemTime::now();
        let active_duration = Duration::from_secs(60);
        let mut bucket = Bucket::new_bucket(current_time, Rate::PerMinute(10), active_duration);

        let time = current_time + active_duration + Duration::from_millis(1);
        bucket.is_conformed(time);

        assert!(
            bucket.is_active(time),
            "bucket must be active right after checking for conformed"
        );
    }

    #[test]
    fn test_is_active_after_is_conform_called() {
        let current_time = SystemTime::now();
        let active_seconds_duration = 60;
        let active_duration = Duration::from_secs(active_seconds_duration);
        let mut bucket = Bucket::new_bucket(current_time, Rate::PerMinute(10), active_duration);

        let time = current_time + active_duration;
        bucket.is_conformed(time);

        let time = time + Duration::from_secs(active_seconds_duration - 1);
        assert!(
            bucket.is_active(time),
            "bucket must be active, because active timeout is not passed"
        );

        let time = time + Duration::from_secs(1) + Duration::from_millis(1);
        assert!(
            !bucket.is_active(time),
            "bucket must not be active, because active timeout is passed"
        );
    }
}
