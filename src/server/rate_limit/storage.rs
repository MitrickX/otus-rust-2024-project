use super::bucket::Bucket;
use std::{collections::HashMap, convert::From};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Key(String);

impl<T: Into<String>> From<T> for Key {
    fn from(value: T) -> Self {
        Key(value.into())
    }
}

// Storage trait is abstraction for where we keep buckets by associatedkeys
pub struct Storage {
    buckets: HashMap<Key, Bucket>,
}

impl Storage {
    /// Add bucket to storage by key
    ///
    /// # Arguments
    ///
    /// * `key` - key of bucket
    /// * `bucket` - bucket to add
    pub fn add(&mut self, key: Key, bucket: Bucket) {
        self.buckets.insert(key, bucket);
    }

    /// Delete associated bucket from storage by key
    ///
    /// # Arguments
    ///
    /// * `key` - key of bucket
    pub fn delete(&mut self, key: Key) {
        self.buckets.remove(&key);
    }

    /// Get bucket from storage by key
    ///
    /// # Arguments
    ///
    /// * `key` - key of bucket
    pub fn get(&mut self, key: Key) -> Option<&Bucket> {
        self.buckets.get(&key)
    }

    /// Has checks existence of bucket in storage by key
    ///
    /// # Arguments
    ///
    /// * `key` - key of bucket
    pub fn has(&mut self, key: Key) -> bool {
        self.buckets.contains_key(&key)
    }

    /// Clear not active buckets from storage
    ///
    /// Returns count of deleted buckets
    pub fn clear_inactive(&mut self) -> usize {
        let keys: Vec<Key> = self
            .buckets
            .iter_mut()
            .filter_map(|(k, b)| if b.is_active() { Some(k.clone()) } else { None })
            .collect();

        for k in &keys {
            self.buckets.remove(k);
        }

        keys.len()
    }
}
