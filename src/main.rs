use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use tracing::{error, info};

mod rpc;
mod storage;
mod types;
mod parser;
mod cache;
mod recover;
mod stats;

#[derive(Parser, Debug, Clone)]
#[command(name = "btc_scanner")]
#[command(about = "High-performance Bitcoin ECDSA R-value reuse scanner", long_about = None)]
struct Cli {
    #[arg(long)]
    start_block: u64,

    #[arg(long)]
    end_block: u64,

    #[arg(long, default_value_t = num_cpus::get() as u32)]
    threads: u32,

    #[arg(long, default_value = "bitcoin_scan.db")]
    db: PathBuf,

    #[arg(long, default_value_t = 50)]
    batch_size: usize,

    #[arg(long, default_value_t = 10)]
    rate_limit: u32,

    #[arg(long, default_value_t = 1)]
    max_requests_per_block: u32,

    #[arg(long, default_value = "https://powerful-wider-violet.btc.quiknode.pro/b519f710ea096c6e01c89438f401cb450f3d8879/")]
    rpc: String,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Logging
    let env_filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .with_thread_names(true)
        .compact()
        .init();

    info!("start={}, end={}, threads={}", cli.start_block, cli.end_block, cli.threads);

    // Initialize DB (WAL) and schema
    let mut db = storage::Database::open(&cli.db)?;
    db.init_schema()?;

    // Initialize R-value cache preloaded from DB
    let mut rcache = cache::RValueCache::new(100_000);
    db.preload_recent_r_values(100_000, &mut rcache)?;

    // RPC client with rate limiting and pooling
    let rpc = rpc::RpcClient::new(cli.rpc.clone(), cli.rate_limit as usize);

    let cfg = types::ScannerConfig {
        start_block: cli.start_block,
        end_block: cli.end_block,
        batch_size: cli.batch_size,
        max_requests_per_block: cli.max_requests_per_block as usize,
        threads: cli.threads as usize,
    };

    let mut runtime_stats = stats::RuntimeStats::default();
    runtime_stats.start();

    if let Err(e) = orchestrate(&rpc, &mut db, &mut rcache, &mut runtime_stats, &cfg).await {
        error!("fatal error: {e}");
    }

    runtime_stats.print_summary();
    db.save_report(&runtime_stats)?;
    Ok(())
}

async fn orchestrate(
    rpc: &rpc::RpcClient,
    db: &mut storage::Database,
    rcache: &mut cache::RValueCache,
    stats: &mut stats::RuntimeStats,
    cfg: &types::ScannerConfig,
) -> Result<()> {
    use futures::stream::{self, StreamExt};

    let block_ranges: Vec<Vec<u64>> = split_range(cfg.start_block, cfg.end_block, cfg.batch_size as u64);

    for batch in block_ranges {
        let blocks = rpc.fetch_blocks_batch(&batch).await?;
        stats.api_calls += 1;
        stats.blocks_scanned += blocks.len() as u64;

        let parsed = stream::iter(blocks)
            .map(|b| async move { parser::parse_block(b) })
            .buffer_unordered(cfg.threads)
            .collect::<Vec<_>>()
            .await;

        for res in parsed {
            let parsed_block = res?;
            stats.transactions_processed += parsed_block.tx_count as u64;
            stats.signatures_processed += parsed_block.sig_count as u64;

            db.insert_signatures_batch(&parsed_block.signatures)?;
            db.upsert_script_stats_batch(&parsed_block.script_stats)?;

            for sig in &parsed_block.signatures {
                if let Some(prev) = rcache.check_and_insert(sig) {
                    stats.r_reuse += 1;
                    if let Some(recovered) = recover::attempt_recover_k_and_priv(sig, &prev) {
                        stats.keys_recovered += 1;
                        db.insert_recovered_key(&recovered)?;
                    }
                }
            }
        }

        db.flush()?;
        stats.report_progress();
    }

    Ok(())
}

fn split_range(start: u64, end: u64, chunk: u64) -> Vec<Vec<u64>> {
    let mut out = Vec::new();
    let mut cur = start;
    while cur <= end {
        let mut v = Vec::new();
        for h in cur..=end {
            v.push(h);
            if (h - cur + 1) >= chunk { break; }
        }
        out.push(v);
        cur = cur.saturating_add(chunk);
        if cur == 0 { break; }
    }
    out
}