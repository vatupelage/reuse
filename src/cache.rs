use crate::types::SignatureRow;
use lru::LruCache;
use parking_lot::Mutex;
use std::collections::HashMap;

pub struct RValueCache {
    cache: Mutex<LruCache<String, SignatureRow>>,
}

impl RValueCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            cache: Mutex::new(LruCache::new(capacity)),
        }
    }

    pub fn check_and_insert(&mut self, sig: &SignatureRow) -> Option<SignatureRow> {
        let mut cache = self.cache.lock();
        
        // Use the actual r_hex string as key instead of hashing
        if let Some(prev) = cache.get(&sig.r) {
            if prev.r == sig.r {
                let prev_clone = prev.clone();
                cache.put(sig.r.clone(), sig.clone());
                return Some(prev_clone);
            }
        }
        
        cache.put(sig.r.clone(), sig.clone());
        None
    }

    pub fn preload(&mut self, signatures: &[SignatureRow]) {
        let mut cache = self.cache.lock();
        for sig in signatures {
            cache.put(sig.r.clone(), sig.clone());
        }
    }
}