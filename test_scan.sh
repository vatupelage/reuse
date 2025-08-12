#!/bin/bash

# Bitcoin ECDSA R-Value Reuse Scanner - Test Script
# This script demonstrates basic usage of the scanner

set -e

echo "🚀 Bitcoin ECDSA Vulnerability Scanner - Test Run"
echo "=================================================="

# Check if binary exists
if [ ! -f "./target/release/btc_scanner" ]; then
    echo "❌ Binary not found. Please build first with: cargo build --release"
    exit 1
fi

# Test with a small range (recent blocks)
echo "📊 Testing scanner with recent blocks..."
echo "   Start block: 800000"
echo "   End block:   800010"
echo "   Threads:     4"
echo "   Batch size:  5"
echo "   Rate limit:  5 req/s"
echo ""

# Run the scanner
./target/release/btc_scanner \
    --start-block 800000 \
    --end-block 800010 \
    --threads 4 \
    --db test_scan_small.db \
    --batch-size 5 \
    --rate-limit 5 \
    --rpc "https://powerful-wider-violet.btc.quiknode.pro/b519f710ea096c6e01c89438f401cb450f3d8879/"

echo ""
echo "✅ Test scan completed!"
echo "📁 Database created: test_scan_small.db"
echo ""

# Show database contents
if [ -f "test_scan_small.db" ]; then
    echo "📊 Database Summary:"
    echo "===================="
    
    # Count signatures
    SIGNATURES=$(sqlite3 test_scan_small.db "SELECT COUNT(*) FROM signatures;" 2>/dev/null || echo "0")
    echo "   Signatures stored: $SIGNATURES"
    
    # Count script types
    SCRIPT_TYPES=$(sqlite3 test_scan_small.db "SELECT COUNT(*) FROM script_analysis;" 2>/dev/null || echo "0")
    echo "   Script types found: $SCRIPT_TYPES"
    
    # Count recovered keys
    RECOVERED=$(sqlite3 test_scan_small.db "SELECT COUNT(*) FROM recovered_keys;" 2>/dev/null || echo "0")
    echo "   Keys recovered: $RECOVERED"
    
    echo ""
    echo "🔍 Sample signatures (first 3):"
    sqlite3 test_scan_small.db "SELECT txid, script_type, r FROM signatures LIMIT 3;" 2>/dev/null || echo "   No signatures found"
fi

echo ""
echo "🎯 Next steps:"
echo "   1. Run larger scans: --start-block 800000 --end-block 800100"
echo "   2. Adjust performance: --threads 12 --batch-size 50"
echo "   3. Monitor rate limits: --rate-limit 10"
echo ""
echo "📚 See README.md for full documentation"
