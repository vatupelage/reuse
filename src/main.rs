use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use tracing::{info, error};

mod cache;
mod parser;
mod recover;
mod rpc;
mod stats;
mod storage;
mod types;

use cache::RValueCache;
use rpc::RpcClient;
use stats::RuntimeStats;
use storage::Database;
use types::ScannerConfig;

#[derive(Parser)]
#[command(name = "btc_scanner")]
#[command(about = "High-performance Bitcoin ECDSA vulnerability scanner")]
struct Cli {
    #[arg(long, default_value = "0")]
    start_block: u32,
    
    #[arg(long, default_value = "1000")]
    end_block: u32,
    
    #[arg(long, default_value = "4")]
    threads: usize,
    
    #[arg(long, default_value = "bitcoin_scan.db")]
    db: String,
    
    #[arg(long, default_value = "10")]
    batch_size: usize,
    
    #[arg(long, default_value = "5")]
    rate_limit: u32,
    
    #[arg(long, default_value = "https://powerful-wider-violet.btc.quiknode.pro/b519f710ea096c6e01c89438f401cb450f3d8879/")]
    rpc: String,
    
    #[arg(long, default_value = "1")]
    max_requests_per_block: u32,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    let cli = Cli::parse();
    
    info!("Starting Bitcoin ECDSA vulnerability scanner");
    info!("Configuration: {:?}", cli);
    
    // Initialize database
    let mut db = Database::open(&cli.db)?;
    info!("Database opened: {}", cli.db);
    
    // Initialize R-value cache
    let mut rcache = RValueCache::new(100_000);
    
    // Preload recent R-values from database
    let recent_sigs = db.preload_recent_r_values(10_000)?;
    rcache.preload(&recent_sigs);
    info!("Preloaded {} recent signatures into R-value cache", recent_sigs.len());
    
    // Initialize RPC client
    let rpc = RpcClient::new(&cli.rpc, cli.rate_limit)?;
    
    // Initialize statistics
    let mut runtime_stats = RuntimeStats::new();
    runtime_stats.start();
    
    // Create scanner configuration
    let config = ScannerConfig {
        start_block: cli.start_block,
        end_block: cli.end_block,
        threads: cli.threads,
        db_path: cli.db,
        batch_size: cli.batch_size,
        rate_limit_per_sec: cli.rate_limit,
        rpc_url: cli.rpc,
        max_requests_per_block: cli.max_requests_per_block,
    };
    
    // Run the scanner
    if let Err(e) = orchestrate(&rpc, &mut db, &mut rcache, &mut runtime_stats, &config).await {
        error!("Scanner failed: {}", e);
        return Err(e);
    }
    
    // Print final summary
    runtime_stats.print_summary();
    
    info!("Scanner completed successfully");
    Ok(())
}

async fn orchestrate(
    rpc: &RpcClient,
    db: &mut Database,
    rcache: &mut RValueCache,
    stats: &mut RuntimeStats,
    cfg: &ScannerConfig,
) -> Result<()> {
    let mut current_block = cfg.start_block;
    
    while current_block <= cfg.end_block {
        let end_block = (current_block + cfg.batch_size as u32 - 1).min(cfg.end_block);
        
        info!("Processing blocks {} to {}", current_block, end_block);
        
        // Fetch blocks in batch
        let blocks = rpc.fetch_blocks_batch(current_block, end_block).await?;
        stats.blocks_processed += blocks.len() as u64;
        
        // Process each block
        for block in blocks {
            // Parse block to extract signatures
            let parsed = parser::parse_block(&block)?;
            stats.signatures_processed += parsed.signatures.len() as u64;
            
            // Insert signatures into database
            if !parsed.signatures.is_empty() {
                db.insert_signatures_batch(&parsed.signatures)?;
                
                // Check for R-value reuse and attempt key recovery
                for sig in &parsed.signatures {
                    if let Some(prev_sig) = rcache.check_and_insert(sig) {
                        stats.r_value_reuse_detected += 1;
                        
                        // Attempt to recover private key
                        if let Some(recovered_key) = recover::attempt_recover_k_and_priv(&prev_sig, sig) {
                            db.insert_recovered_key(&recovered_key)?;
                            stats.keys_recovered += 1;
                            info!("Recovered private key for R-value reuse: {}", recovered_key.private_key);
                        }
                    }
                }
                
                // Update script statistics
                let script_updates: Vec<_> = parsed.script_stats
                    .iter()
                    .map(|(script_type, &count)| types::ScriptStatsUpdate {
                        script_type: script_type.clone(),
                        count,
                    })
                    .collect();
                
                if !script_updates.is_empty() {
                    db.upsert_script_stats_batch(&script_updates)?;
                }
            }
            
            stats.transactions_processed += 1; // Simplified count
        }
        
        current_block = end_block + 1;
        
        // Report progress
        stats.report_progress();
    }
    
    Ok(())
}