use crate::types::SignatureRow;
use lru::LruCache;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use parking_lot::RwLock;
use tracing;

pub struct RValueCache {
    cache: RwLock<LruCache<String, Vec<SignatureRow>>>,
    max_signatures_per_r: usize,
    max_cache_size: usize,
}

impl RValueCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            cache: RwLock::new(LruCache::new(NonZeroUsize::new(capacity).unwrap())),
            max_signatures_per_r: 10, // Limit signatures per R-value
            max_cache_size: capacity,
        }
    }

    pub fn check_and_insert(&self, r_value: &str, signature: SignatureRow) -> Option<SignatureRow> {
        let mut cache = self.cache.write();
        
        // Check if we need to clean up the cache
        if cache.len() > self.max_cache_size * 9 / 10 {
            self.cleanup_cache(&mut cache);
        }
        
        if let Some(existing_signatures) = cache.get_mut(r_value) {
            // Check if this signature already exists
            if existing_signatures.iter().any(|sig| sig.txid == signature.txid && sig.input_index == signature.input_index) {
                return None; // Already exists
            }
            
            // Add new signature with limit
            if existing_signatures.len() < self.max_signatures_per_r {
                existing_signatures.push(signature.clone());
            } else {
                // Replace oldest signature to maintain limit
                existing_signatures.remove(0);
                existing_signatures.push(signature.clone());
            }
            
            // Return the first signature for comparison (oldest)
            Some(existing_signatures[0].clone())
        } else {
            // New R-value
            let mut signatures = Vec::new();
            signatures.push(signature.clone());
            cache.put(r_value.to_string(), signatures);
            None
        }
    }

    pub fn preload(&self, signatures: Vec<SignatureRow>) -> Result<(), Box<dyn std::error::Error>> {
        let mut cache = self.cache.write();
        
        // Limit preloading to prevent memory issues
        let max_preload = 10_000;
        let signatures_to_process = signatures.len().min(max_preload);
        
        for signature in signatures.iter().take(signatures_to_process) {
            if let Some(existing_signatures) = cache.get_mut(&signature.r) {
                if existing_signatures.len() < self.max_signatures_per_r {
                    existing_signatures.push(signature.clone());
                }
            } else {
                let mut signatures_vec = Vec::new();
                signatures_vec.push(signature.clone());
                cache.put(signature.r.clone(), signatures_vec);
            }
        }
        
        tracing::info!("Preloaded {} signatures into cache", signatures_to_process);
        Ok(())
    }
    
    fn cleanup_cache(&self, cache: &mut LruCache<String, Vec<SignatureRow>>) {
        let target_size = self.max_cache_size / 2; // Reduce to 50%
        while cache.len() > target_size {
            if let Some((_, signatures)) = cache.pop_lru() {
                // Drop the signatures to free memory
                drop(signatures);
            }
        }
        tracing::debug!("Cache cleaned up, reduced from {} to {} entries", self.max_cache_size, cache.len());
    }
    
    pub fn get_cache_stats(&self) -> (usize, usize) {
        let cache = self.cache.read();
        let total_entries = cache.len();
        let total_signatures = cache.iter().map(|(_, sigs)| sigs.len()).sum();
        (total_entries, total_signatures)
    }
}
}