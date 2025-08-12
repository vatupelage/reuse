# Bitcoin Scanner Database Analyzer

A comprehensive Python tool to analyze the SQLite database created by the Bitcoin ECDSA vulnerability scanner.

## Features

### 🔍 **Signature Analysis**
- Extract and analyze ECDSA signatures (r, s, z values)
- Identify public keys and Bitcoin addresses
- Classify script types (P2PKH, P2SH, P2WPKH, P2WSH, etc.)
- Show signature distribution across blocks

### 🔄 **R-Value Reuse Detection**
- Find signatures with identical R-values (critical vulnerability)
- Group reused R-values by transaction count
- Identify affected addresses and transactions
- Calculate reuse statistics

### 🔑 **Private Key Recovery Analysis**
- Validate recovered private keys in WIF format
- Verify WIF checksums and format
- Link recovered keys to transaction pairs
- Export private key data securely

### 📍 **Address Analysis**
- Find addresses with most signatures
- Track first/last appearance in blocks
- Analyze script type usage per address
- Identify high-activity addresses

### 📊 **Script Type Statistics**
- Distribution of Bitcoin script types
- Percentage breakdown of script usage
- Historical trends across block ranges

### 💾 **Data Export & Search**
- Export data to JSON format
- Search by address, public key, or transaction ID
- Pattern matching and filtering
- Selective data export by type

## Installation

### Prerequisites
- Python 3.7+
- SQLite database from the Rust scanner

### Install Dependencies
```bash
# Install required packages
pip install -r requirements.txt

# Or install manually
pip install base58
```

### Optional Dependencies
For enhanced analysis and visualization:
```bash
pip install pandas matplotlib seaborn
```

## Usage

### Basic Analysis
```bash
# Run complete database analysis
python db_analyzer.py your_database.db

# Analyze with custom limits
python db_analyzer.py your_database.db --limit 500
```

### Search Functionality
```bash
# Search for specific address
python db_analyzer.py your_database.db --search 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

# Search for transaction ID
python db_analyzer.py your_database.db --search 1234567890abcdef --type txid

# Search for public key pattern
python db_analyzer.py your_database.db --search 02 --type pubkey
```

### Data Export
```bash
# Export all data to JSON
python db_analyzer.py your_database.db --export analysis_data.json

# Export only signatures
python db_analyzer.py your_database.db --export sigs.json --export-type signatures

# Export only recovered keys
python db_analyzer.py your_database.db --export keys.json --export-type recovered_keys
```

## Output Examples

### Database Statistics
```
📊 Database Schema Check:
  ✓ signatures table exists
  ✓ recovered_keys table exists
  ✓ script_analysis table exists

📈 Database Statistics:
  Total Signatures: 1,234,567
  Recovered Keys: 5
  Script Types: 3
  Block Range: 250,000 - 260,000
  Blocks Scanned: 10,001
```

### R-Value Reuse Detection
```
🔄 R-Value Reuse Analysis:
  Found 3 reused R-values:
    R-value: a1b2c3d4e5f6... (used 2 times)
      Transactions: 2
      Addresses: 2
```

### Private Key Recovery
```
🔑 Recovered Private Keys Analysis:
  Found 2 recovered private keys:
    R-value: f1e2d3c4b5a6...
      TX1: 1234567890abcdef...
      TX2: fedcba0987654321...
      WIF: 5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS
      ✓ Valid WIF (compressed)
```

### Address Analysis
```
📍 Address Analysis (showing top 10 by signature count):
    1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
      Signatures: 1,234
      First seen: Block 250,001
      Last seen: Block 259,999
      Script types: P2PKH, P2SH
```

## Database Schema

The analyzer expects the following SQLite tables:

### `signatures` Table
- `txid`: Transaction ID
- `block_height`: Block number
- `address`: Bitcoin address
- `pubkey_hex`: Public key in hex
- `r_hex`: R-value from signature
- `s_hex`: S-value from signature
- `z_hex`: Message hash (z-value)
- `script_type`: Script classification

### `recovered_keys` Table
- `txid1`: First transaction ID
- `txid2`: Second transaction ID
- `r_hex`: Shared R-value
- `private_key_wif`: Recovered private key in WIF format

### `script_analysis` Table
- `script_type`: Script type name
- `count`: Number of occurrences

## Security Considerations

### Private Key Handling
- **NEVER** share recovered private keys
- **NEVER** import them into wallets without verification
- Use `--export-type recovered_keys` to export only key data
- Consider encrypting exported key files

### Data Privacy
- Database may contain sensitive transaction data
- Be cautious when sharing analysis results
- Consider anonymizing addresses in reports

## Performance Tips

### Large Databases
- Use `--limit` to control output size
- Export specific data types instead of full database
- Consider using SQLite indexes for faster queries

### Memory Usage
- Large signature tables may consume significant memory
- Use streaming for very large exports
- Consider chunked processing for massive datasets

## Troubleshooting

### Common Issues

#### Database Connection Failed
```
✗ Database connection failed: [Errno 2] No such file or directory
```
**Solution**: Verify database file path and permissions

#### Schema Check Failed
```
✗ signatures table missing
```
**Solution**: Ensure database was created by the Rust scanner

#### Import Errors
```
ModuleNotFoundError: No module named 'base58'
```
**Solution**: Install dependencies with `pip install -r requirements.txt`

### Performance Issues
- Large databases (>1GB) may be slow
- Use `--limit` to reduce output
- Consider using SSD storage for better I/O

## Advanced Usage

### Custom Queries
Modify the analyzer class to add custom SQL queries:

```python
def custom_analysis(self):
    query = """
    SELECT address, COUNT(*) as sig_count
    FROM signatures 
    WHERE block_height > 800000
    GROUP BY address 
    HAVING sig_count > 100
    ORDER BY sig_count DESC
    """
    results = self.cursor.execute(query).fetchall()
    # Process results...
```

### Integration with Other Tools
```python
# Use with pandas for advanced analysis
import pandas as pd

analyzer = BitcoinDBAnalyzer('database.db')
analyzer.connect()

# Convert to pandas DataFrame
df = pd.read_sql_query("SELECT * FROM signatures", analyzer.conn)
analyzer.disconnect()

# Advanced pandas operations
high_sig_addresses = df.groupby('address').size().nlargest(10)
```

## Contributing

### Adding New Analysis Types
1. Create new method in `BitcoinDBAnalyzer` class
2. Add command-line argument support
3. Update help text and examples
4. Test with sample databases

### Performance Improvements
- Use database indexes for common queries
- Implement query result caching
- Add progress bars for long operations
- Optimize memory usage for large datasets

## License

This tool is provided as-is for educational and research purposes. Use responsibly and in accordance with applicable laws and regulations.

## Support

For issues or questions:
1. Check the troubleshooting section
2. Verify database schema compatibility
3. Ensure all dependencies are installed
4. Test with a small sample database first

---

**⚠️ Warning**: This tool analyzes real Bitcoin transaction data. Handle recovered private keys with extreme caution and never use them without proper verification.

