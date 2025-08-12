use crate::types::SignatureRow;
use lru::LruCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;

pub struct RValueCache {
    cache: Mutex<LruCache<String, SignatureRow>>,
}

impl RValueCache {
    pub fn new(capacity: usize) -> Self {
        let capacity = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(100_000).unwrap());
        Self {
            cache: Mutex::new(LruCache::new(capacity)),
        }
    }

    pub fn check_and_insert(&self, r_value: &str, signature: SignatureRow) -> Option<SignatureRow> {
        let mut cache = self.cache.lock();
        
        if let Some(existing) = cache.get(r_value) {
            // R-value reuse detected!
            Some(existing.clone())
        } else {
            // Insert new signature
            cache.put(r_value.to_string(), signature);
            None
        }
    }

    pub fn preload(&self, signatures: Vec<SignatureRow>) {
        let mut cache = self.cache.lock();
        for sig in signatures {
            cache.put(sig.r.clone(), sig);
        }
    }
}