use anyhow::Result;
use rusqlite::{Connection, params};
use crate::types::{SignatureRow, ScriptType};
use std::collections::HashMap;

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute("PRAGMA journal_mode = WAL", [])?;
        conn.execute("PRAGMA synchronous = NORMAL", [])?;
        conn.execute("PRAGMA cache_size = 10000", [])?;
        conn.execute("PRAGMA temp_store = MEMORY", [])?;
        
        let db = Self { conn };
        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> Result<()> {
        // Create signatures table
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                txid TEXT NOT NULL,
                block_height INTEGER NOT NULL,
                address TEXT NOT NULL,
                pubkey TEXT NOT NULL,
                r TEXT NOT NULL,
                s TEXT NOT NULL,
                z TEXT NOT NULL,
                script_type TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        // Create recovered_keys table
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS recovered_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                txid1 TEXT NOT NULL,
                txid2 TEXT NOT NULL,
                r TEXT NOT NULL,
                private_key TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        // Create script_analysis table - Fixed schema to match code usage
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS script_analysis (
                script_type TEXT PRIMARY KEY,
                count INTEGER NOT NULL,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        // Create indexes for performance
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_signatures_r ON signatures(r)", [])?;
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_signatures_pubkey ON signatures(pubkey)", [])?;
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_signatures_address ON signatures(address)", [])?;
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_signatures_txid ON signatures(txid)", [])?;
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_signatures_block_height ON signatures(block_height)", [])?;
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_recovered_keys_r ON recovered_keys(r)", [])?;
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_recovered_keys_txid1 ON recovered_keys(txid1)", [])?;
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_recovered_keys_txid2 ON recovered_keys(txid2)", [])?;

        Ok(())
    }

    pub fn insert_signatures_batch(&mut self, signatures: &[SignatureRow]) -> Result<()> {
        let tx = self.conn.transaction()?;

        let mut stmt = tx.prepare(
            "INSERT INTO signatures (txid, block_height, address, pubkey, r, s, z, script_type, created_at) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))"
        )?;

        for sig in signatures {
            stmt.execute((
                &sig.txid,
                sig.block_height,
                &sig.address,
                &sig.pubkey,
                &sig.r,
                &sig.s,
                &sig.z,
                format!("{:?}", sig.script_type),
            ))?;
        }

        // Drop the statement before committing
        drop(stmt);
        tx.commit()?;
        Ok(())
    }

    pub fn upsert_script_stats_batch(&mut self, script_stats: &HashMap<ScriptType, u64>) -> Result<()> {
        // Fixed: Connection doesn't need locking, it's already single-threaded
        
        for (script_type, count) in script_stats {
            let script_type_str = format!("{:?}", script_type);
            
            self.conn.execute(
                "INSERT OR REPLACE INTO script_analysis (script_type, count, last_updated) 
                 VALUES (?, ?, datetime('now'))",
                (script_type_str, count),
            )?;
        }
        
        Ok(())
    }

    pub fn insert_recovered_key(&mut self, key: &RecoveredKeyRow) -> Result<()> {
        self.conn.execute(
            "INSERT INTO recovered_keys (txid1, txid2, r, private_key) VALUES (?, ?, ?, ?)",
            params![key.txid1, key.txid2, key.r, key.private_key],
        )?;
        Ok(())
    }

    pub fn preload_recent_r_values(&self, limit: usize) -> Result<Vec<SignatureRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT txid, block_height, address, pubkey, r, s, z, script_type 
             FROM signatures 
             ORDER BY block_height DESC, id DESC 
             LIMIT ?"
        )?;

        let rows = stmt.query_map(params![limit], |row| {
            let script_type_str: String = row.get(7)?;
            let script_type = match script_type_str.as_str() {
                "P2PKH" => ScriptType::P2PKH,
                "P2SH" => ScriptType::P2SH,
                "P2WPKH" => ScriptType::P2WPKH,
                "P2WSH" => ScriptType::P2WSH,
                "P2PK" => ScriptType::P2PK,
                "Multisig" => ScriptType::Multisig,
                _ => ScriptType::NonStandard,
            };

            Ok(SignatureRow {
                txid: row.get(0)?,
                block_height: row.get(1)?,
                address: row.get(2)?,
                pubkey: row.get(3)?,
                r: row.get(4)?,
                s: row.get(5)?,
                z: row.get(6)?,
                script_type,
            })
        })?;

        let mut signatures = Vec::new();
        for row in rows {
            signatures.push(row?);
        }

        Ok(signatures)
    }

    pub fn get_signature_count(&self) -> Result<u64> {
        let count: u64 = self.conn.query_row("SELECT COUNT(*) FROM signatures", [], |row| row.get(0))?;
        Ok(count)
    }

    pub fn get_recovered_key_count(&self) -> Result<u64> {
        let count: u64 = self.conn.query_row("SELECT COUNT(*) FROM recovered_keys", [], |row| row.get(0))?;
        Ok(count)
    }
}