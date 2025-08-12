use std::time::Instant;
use indicatif::{ProgressBar, ProgressStyle};

#[derive(Debug, Default, Clone)]
pub struct RuntimeStats {
    pub start_time: Option<Instant>,
    pub blocks_scanned: u64,
    pub transactions_processed: u64,
    pub signatures_processed: u64,
    pub r_reuse: u64,
    pub keys_recovered: u64,
    pub api_calls: u64,
    progress_bar: Option<ProgressBar>,
}

impl RuntimeStats {
    pub fn start(&mut self) {
        self.start_time = Some(Instant::now());
        
        // Create progress bar
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} [{elapsed_precise}] {msg}")
                .unwrap()
        );
        self.progress_bar = Some(pb);
    }

    pub fn report_progress(&self) {
        if let Some(t0) = self.start_time {
            let elapsed = t0.elapsed().as_secs_f64();
            let sigs_per_sec = if elapsed > 0.0 {
                self.signatures_processed as f64 / elapsed
            } else {
                0.0
            };
            
            let msg = format!(
                "Blocks: {} | Txs: {} | Sigs: {} | R-reuse: {} | Keys: {} | API: {} | Rate: {:.0} sigs/s",
                self.blocks_scanned,
                self.transactions_processed,
                self.signatures_processed,
                self.r_reuse,
                self.keys_recovered,
                self.api_calls,
                sigs_per_sec
            );
            
            if let Some(pb) = &self.progress_bar {
                pb.set_message(msg);
            }
            
            tracing::info!(
                blocks = self.blocks_scanned,
                txs = self.transactions_processed,
                sigs = self.signatures_processed,
                r_reuse = self.r_reuse,
                keys = self.keys_recovered,
                api_calls = self.api_calls,
                rate = format!("{:.0} sigs/s", sigs_per_sec),
                "progress"
            );
        }
    }

    pub fn print_summary(&self) {
        if let Some(t0) = self.start_time {
            let elapsed = t0.elapsed();
            let elapsed_secs = elapsed.as_secs_f64();
            
            println!("\n=== SCAN COMPLETE ===");
            println!("Duration: {:.2}s", elapsed_secs);
            println!("Blocks scanned: {}", self.blocks_scanned);
            println!("Transactions processed: {}", self.transactions_processed);
            println!("Signatures processed: {}", self.signatures_processed);
            println!("R-value reuse detected: {}", self.r_reuse);
            println!("Private keys recovered: {}", self.keys_recovered);
            println!("API calls made: {}", self.api_calls);
            
            if elapsed_secs > 0.0 {
                println!("Average rate: {:.0} signatures/second", 
                    self.signatures_processed as f64 / elapsed_secs);
                println!("API efficiency: {:.1} requests/block", 
                    self.api_calls as f64 / self.blocks_scanned.max(1) as f64);
            }
            
            if self.r_reuse > 0 {
                println!("\n🚨 VULNERABILITIES FOUND! 🚨");
                println!("{} transactions with reused R-values detected", self.r_reuse);
                if self.keys_recovered > 0 {
                    println!("{} private keys successfully recovered", self.keys_recovered);
                }
            } else {
                println!("\n✅ No R-value reuse vulnerabilities detected in scanned blocks");
            }
        }
        
        // Finish progress bar
        if let Some(pb) = &self.progress_bar {
            pb.finish_with_message("Scan complete!");
        }
    }
}