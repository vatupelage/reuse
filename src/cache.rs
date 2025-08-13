use crate::types::SignatureRow;
use lru::LruCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use tracing;

pub struct RValueCache {
    cache: Mutex<LruCache<String, Vec<SignatureRow>>>, // Store multiple signatures per R-value
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
        
        if let Some(existing_signatures) = cache.get(r_value) {
            // R-value reuse detected! Return the first existing signature
            let first_signature = existing_signatures.first().unwrap().clone();
            
            // CRITICAL FIX: Limit signatures per R-value to prevent memory leaks
            let max_signatures_per_r = 10; // Store max 10 signatures per R-value
            
            if existing_signatures.len() < max_signatures_per_r {
                // Add the new signature to the list (within limit)
                let mut updated_signatures = existing_signatures.clone();
                updated_signatures.push(signature);
                cache.put(r_value.to_string(), updated_signatures);
            } else {
                // Log that we're hitting the limit
                tracing::warn!("R-value {} has {} signatures, limiting to prevent memory leak", 
                    r_value, existing_signatures.len());
            }
            
            Some(first_signature)
        } else {
            // No reuse, store the new signature in a list
            let signatures = vec![signature];
            cache.put(r_value.to_string(), signatures);
            None
        }
    }

    pub fn preload(&self, signatures: Vec<SignatureRow>) {
        let mut cache = self.cache.lock();
        
        // Check length before consuming the vector
        let signatures_len = signatures.len();
        let max_preload = 10_000; // Limit preload to 10k signatures
        
        // Limit preloading to prevent memory issues
        let signatures_to_load: Vec<_> = signatures.into_iter().take(max_preload).collect();
        
        for sig in signatures_to_load {
            let r_value = &sig.r;
            if let Some(existing) = cache.get(r_value) {
                let mut updated = existing.clone();
                updated.push(sig.clone());
                cache.put(r_value.clone(), updated);
            } else {
                cache.put(r_value.clone(), vec![sig.clone()]);
            }
        }
        
        // Log if we limited the preload
        if signatures_len > max_preload {
            tracing::warn!("Limited preload to {} signatures to prevent memory issues", max_preload);
        }
    }
}