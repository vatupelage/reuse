# Bitcoin ECDSA R-Value Reuse Scanner

A high-performance, production-grade Bitcoin ECDSA vulnerability scanner that detects reused R-values and recovers private keys using the reused-k attack.

## Features

- **High Performance**: Written in Rust with async/await and multi-threading
- **API Efficient**: Batch RPC requests, caching, and rate limiting
- **Comprehensive Detection**: Supports P2PKH, P2WPKH, P2SH, P2WSH, and non-standard scripts
- **Key Recovery**: Implements ECDSA reused-k attack to recover private keys
- **Database Storage**: SQLite with WAL mode, optimized indexes, and batch operations
- **Real-time Stats**: Progress tracking, performance metrics, and vulnerability reporting

## Requirements

- Ubuntu 20.04+ (tested on Ubuntu 22.04)
- Rust 1.70+ (`rustup install stable`)
- 8GB+ RAM recommended for large scans
- QuickNode RPC endpoint (or other Bitcoin RPC)

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd btc_scanner

# Build optimized release binary
cargo build --release

# The binary will be at: ./target/release/btc_scanner
```

## Usage

### Basic Scan

```bash
./target/release/btc_scanner \
  --start-block 800000 \
  --end-block 800100 \
  --threads 12 \
  --db bitcoin_scan.db \
  --batch-size 50 \
  --rate-limit 10
```

### Full Command Options

```bash
./target/release/btc_scanner \
  --start-block <START_HEIGHT> \
  --end-block <END_HEIGHT> \
  --threads <NUM_THREADS> \
  --db <DATABASE_FILE> \
  --batch-size <BATCH_SIZE> \
  --rate-limit <REQUESTS_PER_SEC> \
  --max-requests-per-block <MAX_REQUESTS> \
  --rpc <RPC_URL>
```

### Parameters

- `--start-block`: Starting block height (inclusive)
- `--end-block`: Ending block height (inclusive)
- `--threads`: Number of worker threads (default: CPU cores)
- `--db`: SQLite database file path (default: bitcoin_scan.db)
- `--batch-size`: Number of blocks to fetch per batch (default: 50)
- `--rate-limit`: Maximum RPC requests per second (default: 10)
- `--max-requests-per-block`: Soft limit on requests per block (default: 1)
- `--rpc`: Bitcoin RPC endpoint URL

## Architecture

### Core Components

1. **RPC Client** (`src/rpc.rs`)
   - Batch requests for multiple blocks
   - In-memory block caching
   - Rate limiting and exponential backoff
   - HTTP/2 connection pooling

2. **Block Parser** (`src/parser.rs`)
   - Raw block hex decoding
   - Transaction and signature extraction
   - Script type classification
   - R, S value extraction from ECDSA signatures

3. **R-Value Cache** (`src/cache.rs`)
   - LRU cache with 100,000 entry capacity
   - R-value collision detection
   - Pre-loaded from database at startup

4. **Key Recovery** (`src/recover.rs`)
   - ECDSA reused-k attack implementation
   - Modular arithmetic for secp256k1
   - Private key recovery and WIF export

5. **Database** (`src/storage.rs`)
   - SQLite with WAL mode
   - Optimized indexes for fast lookups
   - Batch inserts for performance
   - Schema: signatures, recovered_keys, script_analysis

### Performance Features

- **Batch Processing**: Fetch multiple blocks in single RPC calls
- **Caching**: In-memory block cache prevents re-fetching
- **Parallel Parsing**: Multi-threaded signature extraction
- **Database Optimization**: WAL mode, batch inserts, indexed queries
- **Rate Limiting**: Respects RPC endpoint limits

## Database Schema

### Signatures Table
```sql
CREATE TABLE signatures (
    txid TEXT NOT NULL,
    block_height INTEGER NOT NULL,
    address TEXT,
    pubkey TEXT,
    r TEXT NOT NULL,
    s TEXT NOT NULL,
    z TEXT NOT NULL,
    script_type TEXT NOT NULL
);
```

### Recovered Keys Table
```sql
CREATE TABLE recovered_keys (
    txid1 TEXT NOT NULL,
    txid2 TEXT NOT NULL,
    r TEXT NOT NULL,
    private_key TEXT NOT NULL
);
```

### Script Analysis Table
```sql
CREATE TABLE script_analysis (
    script_type TEXT PRIMARY KEY,
    count INTEGER NOT NULL
);
```

## Performance Metrics

- **Target**: >1 million signatures/hour on modern multi-core CPU
- **API Efficiency**: ~1 request/block when possible
- **Memory Usage**: Configurable LRU cache (default: 100k entries)
- **Storage**: SQLite with optimized indexes and batch operations

## Security Considerations

- **Private Key Recovery**: Successfully recovers keys from reused R-values
- **Data Privacy**: All data stored locally in SQLite database
- **RPC Security**: Uses HTTPS for RPC communication
- **Rate Limiting**: Prevents overwhelming RPC endpoints

## Example Output

```
2025-08-11T11:22:11.915706Z  INFO main start=800000, end=800100, threads=12
⠋ [00:01:23] Blocks: 50 | Txs: 1,234 | Sigs: 5,678 | R-reuse: 0 | Keys: 0 | API: 1 | Rate: 76 sigs/s

=== SCAN COMPLETE ===
Duration: 83.45s
Blocks scanned: 100
Transactions processed: 2,468
Signatures processed: 11,356
R-value reuse detected: 0
Private keys recovered: 0
API calls made: 2
Average rate: 136 signatures/second
API efficiency: 0.0 requests/block

✅ No R-value reuse vulnerabilities detected in scanned blocks
```

## Troubleshooting

### Common Issues

1. **RPC Rate Limiting**: Reduce `--rate-limit` if getting 429 errors
2. **Memory Usage**: Adjust cache size in code if running out of RAM
3. **Database Lock**: Ensure no other process is using the database file
4. **Network Issues**: Check RPC endpoint connectivity and firewall settings

### Performance Tuning

- **Threads**: Set to number of CPU cores for optimal performance
- **Batch Size**: Larger batches reduce API calls but increase memory usage
- **Rate Limit**: Match your RPC endpoint's actual limits
- **Database**: Use SSD storage for better I/O performance

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement changes with tests
4. Submit a pull request

## License

MIT License - see LICENSE file for details

## Disclaimer

This tool is for security research and educational purposes only. Use responsibly and only on systems you own or have explicit permission to test. The authors are not responsible for any misuse of this software.
