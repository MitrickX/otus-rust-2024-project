pub mod bucket;
pub mod rate;

use self::bucket::Bucket;
use rate::Rate;
use std::{
    collections::HashMap,
    fmt::Debug,
    hash::Hash,
    time::{Duration, SystemTime},
};

#[derive(Debug)]
pub struct RateLimit<K: PartialEq + Eq + Hash + Clone + Debug> {
    rate: Rate,
    buckets: HashMap<K, Bucket>,
    active_duration: Duration,
}

impl<K: PartialEq + Eq + Hash + Clone + Debug> RateLimit<K> {
    pub fn new(rate: Rate, active_duration: Duration) -> Self {
        Self {
            rate,
            buckets: HashMap::new(),
            active_duration,
        }
    }

    /// Returns true if key is conformed
    ///
    /// # Arguments
    ///
    /// * `key` - associated with some operation key to check is it allowed to do this operation
    pub fn is_conformed(&mut self, key: K) -> bool {
        let current_time = SystemTime::now();
        self.is_conformed_to_time(key, current_time)
    }

    fn is_conformed_to_time(&mut self, key: K, current_time: SystemTime) -> bool {
        let bucket = self
            .buckets
            .entry(key)
            .or_insert(Bucket::new(self.rate, self.active_duration));

        bucket.is_conformed(current_time)
    }

    /// Delete bucket for key from storage
    ///
    /// # Arguments
    ///
    /// * `key` - associated with some operation key to check is it allowed to do this operation
    pub fn reset(&mut self, key: K) {
        self.buckets.remove(&key);
    }

    /// Clear not active buckets from storage
    ///
    /// Returns count of deleted buckets
    pub fn clear_inactive(&mut self) -> usize {
        let current_time = SystemTime::now();
        self.clear_inactive_to_time(current_time)
    }

    fn clear_inactive_to_time(&mut self, current_time: SystemTime) -> usize {
        let remove_keys: Vec<K> = self
            .buckets
            .iter_mut()
            .filter_map(|(k, b)| {
                if !b.is_active(current_time) {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .collect();

        let count = remove_keys.len();

        for k in &remove_keys {
            self.buckets.remove(k);
        }

        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_is_conformed() {
        let current_time = SystemTime::now();
        let key = "test_key".to_owned();
        let n = 2;
        let mut rate_limit = RateLimit::new(Rate::PerMinute(n), Duration::from_secs(120));
        assert!(rate_limit.is_conformed_to_time(key.clone(), current_time));
        assert!(rate_limit.is_conformed_to_time(key.clone(), current_time));
        assert!(!rate_limit.is_conformed_to_time(key.clone(), current_time));

        let current_time = current_time + Duration::from_secs(10);
        // after some time less than 1 minute - we still can't conform
        assert!(!rate_limit.is_conformed_to_time(key.clone(), current_time));

        let current_time = current_time + Duration::from_secs(60);

        // after 1 minute form last conform - 1 token will be released, so we can conform 1 time (and maybe one more, because of edge effects)
        assert!(rate_limit.is_conformed_to_time(key.clone(), current_time));

        let current_time = current_time + Duration::from_secs(120) + Duration::from_millis(1);

        // after 2 minutes from last conform - 2 tokens will be released, so we can conform 2 times (and not more)
        assert!(rate_limit.is_conformed_to_time(key.clone(), current_time));
        assert!(rate_limit.is_conformed_to_time(key.clone(), current_time));
        assert!(!rate_limit.is_conformed_to_time(key.clone(), current_time));
    }

    #[test]
    fn test_clear_inactive() {
        let current_time = SystemTime::now();
        let key1 = "test_key1".to_owned();
        let key2 = "test_key2".to_owned();
        let activity_duration = Duration::from_secs(120);

        let mut rate_limit = RateLimit::new(Rate::PerMinute(10), activity_duration);
        rate_limit.is_conformed_to_time(key1.clone(), current_time);
        rate_limit.is_conformed_to_time(key2.clone(), current_time);

        // after proper time of inactivity of bucket - it will be removed
        let current_time = current_time + activity_duration + Duration::from_millis(1);
        rate_limit.is_conformed_to_time(key1.clone(), current_time); // bucket is still active - so it will live

        let count = rate_limit.clear_inactive_to_time(current_time);
        assert_eq!(
            1, count,
            "one bucket is still active, so only remaining one should be removed"
        );
        assert!(
            rate_limit.buckets.contains_key(key1.as_str()),
            "bucket is still active - so it must live"
        );
        assert!(
            !rate_limit.buckets.contains_key(key2.as_str()),
            "bucket is inactive - so it must be removed"
        );
    }
}
