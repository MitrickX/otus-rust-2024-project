pub mod bucket;
pub mod rate;

use self::bucket::Bucket;
use rate::Rate;
use std::{collections::HashMap, hash::Hash, time::SystemTime};

pub struct RateLimit<K: PartialEq + Eq + Hash + Copy> {
    rate: Rate,
    buckets: HashMap<K, Bucket>,
}

impl<K: PartialEq + Eq + Hash + Copy> RateLimit<K> {
    pub fn new(rate: Rate) -> Self {
        Self {
            rate,
            buckets: HashMap::new(),
        }
    }

    /// Returns true if key is conformed
    ///
    /// # Arguments
    ///
    /// * `key` - associated with some operation key to check is it allowed to do this operation
    pub fn is_conformed(&mut self, key: K) -> bool {
        let current_time = self.get_current_time();
        let bucket = self.buckets.entry(key).or_insert(Bucket::new(self.rate));

        bucket.is_conformed(current_time)
    }

    fn get_current_time(&self) -> SystemTime {
        SystemTime::now()
    }
}

// TODO: add tests
// TODO: cleaning method
// /// Clear not active buckets from storage
// ///
// /// Returns count of deleted buckets
// pub fn clear_inactive(&mut self) -> usize {
//     let keys: Vec<Key> = self
//         .buckets
//         .iter_mut()
//         .filter_map(|(k, b)| if b.is_active() { Some(k.clone()) } else { None })
//         .collect();

//     for k in &keys {
//         self.buckets.remove(k);
//     }

//     keys.len()
// }
