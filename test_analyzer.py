#!/usr/bin/env python3
"""
Test script for the Bitcoin Database Analyzer
Creates a sample database and demonstrates analysis features
"""

import sqlite3
import os
from db_analyzer import BitcoinDBAnalyzer

def create_sample_database():
    """Create a sample database for testing"""
    db_path = "test_sample.db"
    
    # Remove existing test database
    if os.path.exists(db_path):
        os.remove(db_path)
    
    # Create database and tables
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute("""
        CREATE TABLE signatures (
            txid TEXT PRIMARY KEY,
            block_height INTEGER,
            address TEXT,
            pubkey_hex TEXT,
            r_hex TEXT,
            s_hex TEXT,
            z_hex TEXT,
            script_type TEXT
        )
    """)
    
    cursor.execute("""
        CREATE TABLE recovered_keys (
            txid1 TEXT,
            txid2 TEXT,
            r_hex TEXT,
            private_key_wif TEXT
        )
    """)
    
    cursor.execute("""
        CREATE TABLE script_analysis (
            script_type TEXT PRIMARY KEY,
            count INTEGER
        )
    """)
    
    # Insert sample data
    sample_signatures = [
        ("tx1_1234567890abcdef", 250000, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 
         "02a1b2c3d4e5f6", "r1_value_here", "s1_value_here", "z1_value_here", "P2PKH"),
        ("tx2_fedcba0987654321", 250001, "1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8", 
         "03b2c3d4e5f6g7", "r2_value_here", "s2_value_here", "z2_value_here", "P2SH"),
        ("tx3_abcdef1234567890", 250002, "1C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9", 
         "04c3d4e5f6g7h8", "r1_value_here", "s3_value_here", "z3_value_here", "P2PKH"),
        ("tx4_1234567890fedcba", 250003, "1D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0", 
         "05d4e5f6g7h8i9", "r4_value_here", "s4_value_here", "z4_value_here", "P2WPKH"),
        ("tx5_fedcba1234567890", 250004, "1E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1", 
         "06e5f6g7h8i9j0", "r5_value_here", "s5_value_here", "z5_value_here", "P2WSH"),
    ]
    
    cursor.executemany("""
        INSERT INTO signatures (txid, block_height, address, pubkey_hex, r_hex, s_hex, z_hex, script_type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, sample_signatures)
    
    # Insert sample recovered keys (demonstrating R-value reuse)
    sample_keys = [
        ("tx1_1234567890abcdef", "tx3_abcdef1234567890", "r1_value_here", 
         "5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS")
    ]
    
    cursor.executemany("""
        INSERT INTO recovered_keys (txid1, txid2, r_hex, private_key_wif)
        VALUES (?, ?, ?, ?)
    """, sample_keys)
    
    # Insert script analysis
    script_stats = [
        ("P2PKH", 2),
        ("P2SH", 1),
        ("P2WPKH", 1),
        ("P2WSH", 1)
    ]
    
    cursor.executemany("""
        INSERT INTO script_analysis (script_type, count)
        VALUES (?, ?)
    """, script_stats)
    
    # Create indexes for better performance
    cursor.execute("CREATE INDEX idx_signatures_r ON signatures(r_hex)")
    cursor.execute("CREATE INDEX idx_signatures_address ON signatures(address)")
    cursor.execute("CREATE INDEX idx_signatures_block ON signatures(block_height)")
    
    conn.commit()
    conn.close()
    
    print(f"✓ Created sample database: {db_path}")
    return db_path

def test_analyzer():
    """Test the database analyzer with sample data"""
    print("🧪 Testing Bitcoin Database Analyzer")
    print("=" * 40)
    
    # Create sample database
    db_path = create_sample_database()
    
    # Test analyzer
    analyzer = BitcoinDBAnalyzer(db_path)
    
    print("\n🔍 Running full analysis...")
    analyzer.run_full_analysis()
    
    print("\n🔍 Testing search functionality...")
    analyzer.connect()
    analyzer.search_by_pattern("1A1zP1", "address")
    analyzer.disconnect()
    
    print("\n💾 Testing export functionality...")
    analyzer.connect()
    analyzer.export_data("test_export.json", "all")
    analyzer.disconnect()
    
    # Cleanup
    if os.path.exists(db_path):
        os.remove(db_path)
        print(f"\n✓ Cleaned up test database: {db_path}")
    
    if os.path.exists("test_export.json"):
        os.remove("test_export.json")
        print(f"✓ Cleaned up test export: test_export.json")
    
    print("\n✅ All tests completed successfully!")

if __name__ == "__main__":
    test_analyzer()

