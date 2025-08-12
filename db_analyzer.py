#!/usr/bin/env python3
"""
Bitcoin ECDSA Vulnerability Scanner - Database Analyzer
Analyzes the SQLite database created by the Rust scanner for:
- Public keys and addresses
- Recovered private keys
- Signature analysis
- R-value reuse patterns
- Script type statistics
"""

import sqlite3
import argparse
import json
import hashlib
import base58
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from collections import defaultdict, Counter
import sys
from pathlib import Path

@dataclass
class SignatureInfo:
    txid: str
    block_height: int
    address: str
    pubkey_hex: str
    r_hex: str
    s_hex: str
    z_hex: str
    script_type: str

@dataclass
class RecoveredKeyInfo:
    txid1: str
    txid2: str
    r_hex: str
    private_key_wif: str

@dataclass
class ScriptStats:
    script_type: str
    count: int

class BitcoinDBAnalyzer:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = None
        self.cursor = None
        
    def connect(self):
        """Connect to the SQLite database"""
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
            self.cursor = self.conn.cursor()
            print(f"✓ Connected to database: {self.db_path}")
        except sqlite3.Error as e:
            print(f"✗ Database connection failed: {e}")
            sys.exit(1)
    
    def disconnect(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            print("✓ Database connection closed")
    
    def check_schema(self):
        """Check if the database has the expected schema"""
        try:
            tables = self.cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name IN ('signatures', 'recovered_keys', 'script_analysis')
            """).fetchall()
            
            table_names = [row[0] for row in tables]
            expected_tables = ['signatures', 'recovered_keys', 'script_analysis']
            
            print("\n📊 Database Schema Check:")
            for table in expected_tables:
                if table in table_names:
                    print(f"  ✓ {table} table exists")
                else:
                    print(f"  ✗ {table} table missing")
            
            return len(table_names) == len(expected_tables)
        except sqlite3.Error as e:
            print(f"✗ Schema check failed: {e}")
            return False
    
    def inspect_schema(self):
        """Inspect the actual database schema to see what columns exist"""
        try:
            print(f"\n🔍 Database Schema Inspection:")
            
            # Get table schemas
            for table_name in ['signatures', 'recovered_keys', 'script_analysis']:
                try:
                    schema = self.cursor.execute(f"PRAGMA table_info({table_name})").fetchall()
                    print(f"\n  Table: {table_name}")
                    for col in schema:
                        print(f"    {col[1]} ({col[2]}) - {'NOT NULL' if col[3] else 'NULL'}")
                except sqlite3.Error:
                    print(f"    Table {table_name} not accessible")
            
            # Show sample data from signatures table
            try:
                sample = self.cursor.execute("SELECT * FROM signatures LIMIT 1").fetchone()
                if sample:
                    print(f"\n  Sample signature row:")
                    for i, col in enumerate(sample):
                        print(f"    Column {i}: {col}")
            except sqlite3.Error as e:
                print(f"    Could not read sample: {e}")
                
        except sqlite3.Error as e:
            print(f"✗ Schema inspection failed: {e}")
    
    def get_database_stats(self):
        """Get overall database statistics"""
        try:
            # Count records in each table
            sig_count = self.cursor.execute("SELECT COUNT(*) FROM signatures").fetchone()[0]
            key_count = self.cursor.execute("SELECT COUNT(*) FROM recovered_keys").fetchone()[0]
            script_count = self.cursor.execute("SELECT COUNT(*) FROM script_analysis").fetchone()[0]
            
            # Get block range
            block_range = self.cursor.execute("""
                SELECT MIN(block_height), MAX(block_height) FROM signatures
            """).fetchone()
            
            min_block, max_block = block_range if block_range[0] else (0, 0)
            
            print(f"\n📈 Database Statistics:")
            print(f"  Total Signatures: {sig_count:,}")
            print(f"  Recovered Keys: {key_count:,}")
            print(f"  Script Types: {script_count}")
            print(f"  Block Range: {min_block:,} - {max_block:,}")
            print(f"  Blocks Scanned: {max_block - min_block + 1:,}")
            
            return {
                'signatures': sig_count,
                'recovered_keys': key_count,
                'script_types': script_count,
                'min_block': min_block,
                'max_block': max_block
            }
        except sqlite3.Error as e:
            print(f"✗ Failed to get database stats: {e}")
            return {}
    
    def analyze_signatures(self, limit: int = 100):
        """Analyze signature data"""
        try:
            print(f"\n🔍 Signature Analysis (showing first {limit}):")
            
            # First, let's see what columns actually exist
            schema = self.cursor.execute("PRAGMA table_info(signatures)").fetchall()
            columns = [col[1] for col in schema]
            print(f"  Available columns: {', '.join(columns)}")
            
            # Build dynamic query based on available columns
            select_cols = []
            if 'txid' in columns:
                select_cols.append('txid')
            if 'block_height' in columns:
                select_cols.append('block_height')
            if 'address' in columns:
                select_cols.append('address')
            if 'pubkey_hex' in columns:
                select_cols.append('pubkey_hex')
            if 'r_hex' in columns:
                select_cols.append('r_hex')
            if 's_hex' in columns:
                select_cols.append('s_hex')
            if 'z_hex' in columns:
                select_cols.append('z_hex')
            if 'script_type' in columns:
                select_cols.append('script_type')
            
            if not select_cols:
                print("  No recognizable columns found")
                return {}
            
            query = f"SELECT {', '.join(select_cols)} FROM signatures ORDER BY block_height DESC, txid LIMIT ?"
            signatures = self.cursor.execute(query, (limit,)).fetchall()
            
            if not signatures:
                print("  No signatures found in database")
                return {}
            
            # Show sample signatures
            print(f"\n  Sample Signatures:")
            for i, sig in enumerate(signatures[:5], 1):
                print(f"    {i}. ", end="")
                for j, col in enumerate(select_cols):
                    if col == 'block_height':
                        print(f"Block {sig[j]:,} | ", end="")
                    elif col == 'txid':
                        print(f"{sig[j][:16]}... | ", end="")
                    elif col == 'address':
                        print(f"Addr: {sig[j] or 'N/A'} | ", end="")
                    elif col == 'script_type':
                        print(f"Script: {sig[j]}", end="")
                print()
            
            # Count by script type if available
            if 'script_type' in columns:
                script_types = Counter()
                for sig in signatures:
                    script_idx = select_cols.index('script_type')
                    script_types[sig[script_idx]] += 1
                
                print(f"\n  Script Type Distribution:")
                for script_type, count in script_types.most_common():
                    print(f"    {script_type}: {count:,}")
            
            return {
                'columns': select_cols,
                'sample_count': len(signatures)
            }
            
        except sqlite3.Error as e:
            print(f"✗ Signature analysis failed: {e}")
            return {}
    
    def analyze_r_value_reuse(self):
        """Analyze R-value reuse patterns"""
        try:
            print(f"\n🔄 R-Value Reuse Analysis:")
            
            # Check if r_hex column exists
            schema = self.cursor.execute("PRAGMA table_info(signatures)").fetchall()
            columns = [col[1] for col in schema]
            
            if 'r_hex' not in columns:
                print("  R-value column 'r_hex' not found in signatures table")
                print(f"  Available columns: {', '.join(columns)}")
                return {}
            
            # Find R-values that appear multiple times
            r_reuse = self.cursor.execute("""
                SELECT r_hex, COUNT(*) as count, 
                       GROUP_CONCAT(txid) as txids,
                       GROUP_CONCAT(address) as addresses
                FROM signatures 
                WHERE r_hex IS NOT NULL AND r_hex != ''
                GROUP BY r_hex 
                HAVING COUNT(*) > 1
                ORDER BY count DESC
            """).fetchall()
            
            if not r_reuse:
                print("  No R-value reuse detected")
                return {}
            
            print(f"  Found {len(r_reuse)} reused R-values:")
            
            reuse_stats = {}
            for reuse in r_reuse:
                count = reuse['count']
                r_hex = reuse['r_hex']
                txids = reuse['txids'].split(',')
                addresses = reuse['addresses'].split(',')
                
                print(f"    R-value: {r_hex[:16]}... (used {count} times)")
                print(f"      Transactions: {len(txids)}")
                print(f"      Addresses: {len(set(addresses))}")
                
                reuse_stats[r_hex] = {
                    'count': count,
                    'txids': txids,
                    'addresses': list(set(addresses))
                }
            
            return reuse_stats
            
        except sqlite3.Error as e:
            print(f"✗ R-value reuse analysis failed: {e}")
            return {}
    
    def analyze_recovered_keys(self):
        """Analyze recovered private keys"""
        try:
            print(f"\n🔑 Recovered Private Keys Analysis:")
            
            # Check schema first
            schema = self.cursor.execute("PRAGMA table_info(recovered_keys)").fetchall()
            columns = [col[1] for col in schema]
            print(f"  Available columns: {', '.join(columns)}")
            
            # Build query based on available columns
            select_cols = []
            if 'txid1' in columns:
                select_cols.append('txid1')
            if 'txid2' in columns:
                select_cols.append('txid2')
            if 'r_hex' in columns:
                select_cols.append('r_hex')
            if 'private_key_wif' in columns:
                select_cols.append('private_key_wif')
            
            if not select_cols:
                print("  No recognizable columns found")
                return {}
            
            query = f"SELECT {', '.join(select_cols)} FROM recovered_keys ORDER BY txid1"
            keys = self.cursor.execute(query).fetchall()
            
            if not keys:
                print("  No private keys recovered")
                return {}
            
            print(f"  Found {len(keys)} recovered private keys:")
            
            key_info = []
            for key in keys:
                print(f"    ", end="")
                for j, col in enumerate(select_cols):
                    if col == 'r_hex':
                        print(f"R-value: {key[j][:16]}... | ", end="")
                    elif col == 'txid1':
                        print(f"TX1: {key[j][:16]}... | ", end="")
                    elif col == 'txid2':
                        print(f"TX2: {key[j][:16]}... | ", end="")
                    elif col == 'private_key_wif':
                        print(f"WIF: {key[j]}")
                        
                        # Validate WIF format if possible
                        try:
                            decoded = base58.b58decode(key[j])
                            if len(decoded) == 37:  # compressed WIF
                                checksum = decoded[33:37]
                                expected_checksum = hashlib.sha256(
                                    hashlib.sha256(decoded[:-4]).digest()
                                ).digest()[:4]
                                
                                if checksum == expected_checksum:
                                    print(f"      ✓ Valid WIF (compressed)")
                                else:
                                    print(f"      ✗ Invalid checksum")
                            else:
                                print(f"      ✗ Invalid WIF length")
                        except Exception as e:
                            print(f"      ✗ WIF validation failed: {e}")
                
                print()
                key_info.append(dict(zip(select_cols, key)))
            
            return key_info
            
        except sqlite3.Error as e:
            print(f"✗ Recovered keys analysis failed: {e}")
            return {}
    
    def analyze_addresses(self, limit: int = 50):
        """Analyze address patterns and balances"""
        try:
            print(f"\n📍 Address Analysis (showing top {limit} by signature count):")
            
            # Check if address column exists
            schema = self.cursor.execute("PRAGMA table_info(signatures)").fetchall()
            columns = [col[1] for col in schema]
            
            if 'address' not in columns:
                print("  Address column not found in signatures table")
                print(f"  Available columns: {', '.join(columns)}")
                return {}
            
            # Get addresses with most signatures
            addresses = self.cursor.execute("""
                SELECT address, COUNT(*) as sig_count,
                       MIN(block_height) as first_seen,
                       MAX(block_height) as last_seen,
                       GROUP_CONCAT(DISTINCT script_type) as script_types
                FROM signatures 
                WHERE address IS NOT NULL AND address != ''
                GROUP BY address 
                ORDER BY sig_count DESC
                LIMIT ?
            """, (limit,)).fetchall()
            
            if not addresses:
                print("  No addresses found")
                return {}
            
            address_stats = {}
            for addr in addresses:
                sig_count = addr['sig_count']
                address = addr['address']
                first_seen = addr['first_seen']
                last_seen = addr['last_seen']
                script_types = set(addr['script_types'].split(','))
                
                print(f"    {address}")
                print(f"      Signatures: {sig_count:,}")
                print(f"      First seen: Block {first_seen:,}")
                print(f"      Last seen: Block {last_seen:,}")
                print(f"      Script types: {', '.join(script_types)}")
                
                address_stats[address] = {
                    'signature_count': sig_count,
                    'first_seen': first_seen,
                    'last_seen': last_seen,
                    'script_types': list(script_types)
                }
            
            return address_stats
            
        except sqlite3.Error as e:
            print(f"✗ Address analysis failed: {e}")
            return {}
    
    def analyze_script_types(self):
        """Analyze script type distribution"""
        try:
            print(f"\n📜 Script Type Analysis:")
            
            # Get script type statistics
            script_stats = self.cursor.execute("""
                SELECT script_type, COUNT(*) as count
                FROM script_analysis
                ORDER BY count DESC
            """).fetchall()
            
            if not script_stats:
                print("  No script type data found")
                return {}
            
            total_scripts = sum(row['count'] for row in script_stats)
            print(f"  Total scripts analyzed: {total_scripts:,}")
            print(f"  Script type distribution:")
            
            script_data = {}
            for stat in script_stats:
                script_type = stat['script_type']
                count = stat['count']
                percentage = (count / total_scripts) * 100
                
                print(f"    {script_type}: {count:,} ({percentage:.1f}%)")
                script_data[script_type] = {
                    'count': count,
                    'percentage': percentage
                }
            
            return script_data
            
        except sqlite3.Error as e:
            print(f"✗ Script type analysis failed: {e}")
            return {}
    
    def search_by_pattern(self, pattern: str, search_type: str = 'all'):
        """Search for specific patterns in the database"""
        try:
            print(f"\n🔍 Pattern Search: '{pattern}' (type: {search_type})")
            
            # Check available columns first
            schema = self.cursor.execute("PRAGMA table_info(signatures)").fetchall()
            columns = [col[1] for col in schema]
            
            if search_type == 'all' or search_type == 'address':
                if 'address' in columns:
                    # Search addresses
                    addresses = self.cursor.execute("""
                        SELECT DISTINCT address, COUNT(*) as sig_count
                        FROM signatures 
                        WHERE address LIKE ?
                        GROUP BY address
                        ORDER BY sig_count DESC
                        LIMIT 20
                    """, (f'%{pattern}%',)).fetchall()
                    
                    if addresses:
                        print(f"  Address matches ({len(addresses)}):")
                        for addr in addresses:
                            print(f"    {addr['address']} ({addr['sig_count']} signatures)")
                else:
                    print("  Address column not available")
            
            if search_type == 'all' or search_type == 'pubkey':
                if 'pubkey_hex' in columns:
                    # Search public keys
                    pubkeys = self.cursor.execute("""
                        SELECT DISTINCT pubkey_hex, COUNT(*) as sig_count
                        FROM signatures 
                        WHERE pubkey_hex LIKE ?
                        GROUP BY pubkey_hex
                        ORDER BY sig_count DESC
                        LIMIT 20
                    """, (f'%{pattern}%',)).fetchall()
                    
                    if pubkeys:
                        print(f"  Public key matches ({len(pubkeys)}):")
                        for pk in pubkeys:
                            print(f"    {pk['pubkey_hex'][:32]}... ({pk['sig_count']} signatures)")
                else:
                    print("  Public key column not available")
            
            if search_type == 'all' or search_type == 'txid':
                if 'txid' in columns:
                    # Search transaction IDs
                    txids = self.cursor.execute("""
                        SELECT txid, block_height, address, script_type
                        FROM signatures 
                        WHERE txid LIKE ?
                        ORDER BY block_height DESC
                        LIMIT 20
                    """, (f'%{pattern}%',)).fetchall()
                    
                    if txids:
                        print(f"  Transaction matches ({len(txids)}):")
                        for tx in txids:
                            print(f"    {tx['txid']} (Block {tx['block_height']:,})")
                else:
                    print("  Transaction ID column not available")
            
        except sqlite3.Error as e:
            print(f"✗ Pattern search failed: {e}")
    
    def export_data(self, output_file: str, data_type: str = 'all'):
        """Export data to JSON file"""
        try:
            print(f"\n💾 Exporting data to {output_file}...")
            
            export_data = {}
            
            if data_type in ['all', 'signatures']:
                # Get all columns for signatures
                schema = self.cursor.execute("PRAGMA table_info(signatures)").fetchall()
                columns = [col[1] for col in schema]
                select_cols = ', '.join(columns)
                
                signatures = self.cursor.execute(f"SELECT {select_cols} FROM signatures LIMIT 10000").fetchall()
                export_data['signatures'] = [dict(zip(columns, sig)) for sig in signatures]
            
            if data_type in ['all', 'recovered_keys']:
                # Get all columns for recovered keys
                schema = self.cursor.execute("PRAGMA table_info(recovered_keys)").fetchall()
                columns = [col[1] for col in schema]
                select_cols = ', '.join(columns)
                
                keys = self.cursor.execute(f"SELECT {select_cols} FROM recovered_keys").fetchall()
                export_data['recovered_keys'] = [dict(zip(columns, key)) for key in keys]
            
            if data_type in ['all', 'script_analysis']:
                scripts = self.cursor.execute("SELECT * FROM script_analysis").fetchall()
                export_data['script_analysis'] = [dict(script) for script in scripts]
            
            with open(output_file, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            print(f"✓ Exported {len(export_data)} data types to {output_file}")
            
        except Exception as e:
            print(f"✗ Export failed: {e}")
    
    def run_full_analysis(self):
        """Run complete database analysis"""
        print("🚀 Bitcoin Scanner Database Analysis")
        print("=" * 50)
        
        # Connect and check schema
        self.connect()
        if not self.check_schema():
            print("⚠️  Database schema incomplete - some analysis may fail")
        
        # Inspect actual schema first
        self.inspect_schema()
        
        # Run all analyses
        stats = self.get_database_stats()
        sig_analysis = self.analyze_signatures()
        r_reuse = self.analyze_r_value_reuse()
        recovered_keys = self.analyze_recovered_keys()
        address_analysis = self.analyze_addresses()
        script_analysis = self.analyze_script_types()
        
        # Summary
        print(f"\n📊 Analysis Summary:")
        print(f"  Database contains {stats.get('signatures', 0):,} signatures")
        print(f"  {len(r_reuse)} R-value reuse patterns detected")
        print(f"  {len(recovered_keys)} private keys recovered")
        print(f"  {stats.get('script_types', 0)} script types analyzed")
        
        self.disconnect()

def main():
    parser = argparse.ArgumentParser(
        description="Bitcoin Scanner Database Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python db_analyzer.py scan.db                    # Full analysis
  python db_analyzer.py scan.db --search 1A1zP1   # Search for address
  python db_analyzer.py scan.db --export data.json # Export to JSON
  python db_analyzer.py scan.db --search 1234 --type txid  # Search TXID
        """
    )
    
    parser.add_argument('database', help='Path to SQLite database file')
    parser.add_argument('--search', help='Search for specific pattern')
    parser.add_argument('--type', choices=['all', 'address', 'pubkey', 'txid'], 
                       default='all', help='Search type for pattern search')
    parser.add_argument('--export', help='Export data to JSON file')
    parser.add_argument('--export-type', choices=['all', 'signatures', 'recovered_keys', 'script_analysis'],
                       default='all', help='Type of data to export')
    parser.add_argument('--limit', type=int, default=100, help='Limit for analysis output')
    
    args = parser.parse_args()
    
    # Check if database exists
    if not Path(args.database).exists():
        print(f"✗ Database file not found: {args.database}")
        sys.exit(1)
    
    # Create analyzer and run
    analyzer = BitcoinDBAnalyzer(args.database)
    
    if args.search:
        analyzer.connect()
        analyzer.search_by_pattern(args.search, args.type)
        analyzer.disconnect()
    elif args.export:
        analyzer.connect()
        analyzer.export_data(args.export, args.export_type)
        analyzer.disconnect()
    else:
        analyzer.run_full_analysis()

if __name__ == "__main__":
    main()
