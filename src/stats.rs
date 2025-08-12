use indicatif::ProgressBar;
use std::time::Instant;
use tracing::info;

#[derive(Debug, Default)]
pub struct RuntimeStats {
    pub blocks_processed: u64,
    pub transactions_processed: u64,
    pub signatures_processed: u64,
    pub r_value_reuse_detected: u64,
    pub keys_recovered: u64,
    pub api_calls: u64,
    start_time: Option<Instant>,
    progress_bar: Option<ProgressBar>,
}

impl RuntimeStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn start(&mut self) {
        self.start_time = Some(Instant::now());
        self.progress_bar = Some(ProgressBar::new_spinner());
        info!("Scanner started");
    }

    pub fn report_progress(&self) {
        if let Some(progress_bar) = &self.progress_bar {
            let message = format!(
                "Blocks: {} | Txs: {} | Sigs: {} | R-reuse: {} | Keys: {} | API calls: {}",
                self.blocks_processed,
                self.transactions_processed,
                self.signatures_processed,
                self.r_value_reuse_detected,
                self.keys_recovered,
                self.api_calls,
            );
            progress_bar.set_message(message);
        }

        info!(
            "Progress - Blocks: {}, Txs: {}, Sigs: {}, R-reuse: {}, Keys: {}, API: {}",
            self.blocks_processed,
            self.transactions_processed,
            self.signatures_processed,
            self.r_value_reuse_detected,
            self.keys_recovered,
            self.api_calls,
        );
    }

    pub fn print_summary(&self) {
        if let Some(start_time) = self.start_time {
            let duration = start_time.elapsed();
            
            info!("=");
            info!("SCAN COMPLETED");
            info!("=");
            info!("Duration: {:.2?}", duration);
            info!("Blocks processed: {}", self.blocks_processed);
            info!("Transactions processed: {}", self.transactions_processed);
            info!("Signatures processed: {}", self.signatures_processed);
            info!("R-value reuse detected: {}", self.r_value_reuse_detected);
            info!("Private keys recovered: {}", self.keys_recovered);
            info!("API calls made: {}", self.api_calls);
            
            if duration.as_secs() > 0 {
                let blocks_per_sec = self.blocks_processed as f64 / duration.as_secs() as f64;
                let sigs_per_sec = self.signatures_processed as f64 / duration.as_secs() as f64;
                let api_per_sec = self.api_calls as f64 / duration.as_secs() as f64;
                
                info!("Performance:");
                info!("  Blocks per second: {:.2}", blocks_per_sec);
                info!("  Signatures per second: {:.2}", sigs_per_sec);
                info!("  API calls per second: {:.2}", api_per_sec);
            }
            
            if self.r_value_reuse_detected > 0 {
                info!("");
                info!("VULNERABILITIES DETECTED:");
                info!("  R-value reuse: {} instances", self.r_value_reuse_detected);
                info!("  Private keys recovered: {}", self.keys_recovered);
                info!("");
                info!("CRITICAL: These vulnerabilities could allow attackers to steal funds!");
            }
        }
    }
}