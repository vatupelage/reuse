use std::time::Instant;
use indicatif::ProgressBar;

#[derive(Debug)]
pub struct RuntimeStats {
    start_time: Instant,
    pub blocks_processed: u64,
    pub transactions_processed: u64,
    pub signatures_processed: u64,
    pub r_value_reuse_detected: u64,
    pub keys_recovered: u64,
    pub api_requests: u64,
}

impl RuntimeStats {
    pub fn start() -> Self {
        Self {
            start_time: Instant::now(),
            blocks_processed: 0,
            transactions_processed: 0,
            signatures_processed: 0,
            r_value_reuse_detected: 0,
            keys_recovered: 0,
            api_requests: 0,
        }
    }

    pub fn report_progress(&self) {
        let elapsed = self.start_time.elapsed();
        let rate = if elapsed.as_secs() > 0 {
            self.signatures_processed / elapsed.as_secs()
        } else {
            0
        };

        info!(
            "progress blocks={} txs={} sigs={} r_reuse={} keys={} API={} rate=\"{}/s\"",
            self.blocks_processed,
            self.transactions_processed,
            self.signatures_processed,
            self.r_value_reuse_detected,
            self.keys_recovered,
            self.api_requests,
            rate
        );
    }

    pub fn print_summary(&self) {
        let elapsed = self.start_time.elapsed();
        let total_blocks = self.blocks_processed;
        let total_txs = self.transactions_processed;
        let total_sigs = self.signatures_processed;
        let reuse_count = self.r_value_reuse_detected;
        let keys_count = self.keys_recovered;
        let api_count = self.api_requests;

        info!("=== SCAN COMPLETE ===");
        info!("Duration: {:?}", elapsed);
        info!("Blocks processed: {}", total_blocks);
        info!("Transactions processed: {}", total_txs);
        info!("Signatures processed: {}", total_sigs);
        info!("R-value reuse detected: {}", reuse_count);
        info!("Private keys recovered: {}", keys_count);
        info!("API requests made: {}", api_count);
        
        if elapsed.as_secs() > 0 {
            let sigs_per_sec = total_sigs as f64 / elapsed.as_secs() as f64;
            let blocks_per_sec = total_blocks as f64 / elapsed.as_secs() as f64;
            info!("Performance: {:.0} sigs/sec, {:.2} blocks/sec", sigs_per_sec, blocks_per_sec);
        }
    }
}