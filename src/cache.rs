use lru::LruCache;
use std::num::NonZeroUsize;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use crate::types::SignatureRow;

#[derive(Debug)]
pub struct RValueCache {
    cache: LruCache<u64, SignatureRow>,
}

impl RValueCache {
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap();
        Self {
            cache: LruCache::new(cap),
        }
    }

    fn key_for_r(r_hex: &str) -> u64 {
        let mut h = DefaultHasher::new();
        r_hex.hash(&mut h);
        h.finish()
    }

    // Returns previous matching signature if r collision detected (exact r_hex match)
    pub fn check_and_insert(&mut self, sig: &SignatureRow) -> Option<SignatureRow> {
        let key = Self::key_for_r(&sig.r_hex);
        if let Some(prev) = self.cache.get(&key) {
            if prev.r_hex == sig.r_hex {
                let prev_clone = prev.clone();
                self.cache.put(key, sig.clone());
                return Some(prev_clone);
            }
        }
        self.cache.put(key, sig.clone());
        None
    }

    pub fn insert_only(&mut self, sig: SignatureRow) {
        let key = Self::key_for_r(&sig.r_hex);
        self.cache.put(key, sig);
    }
}