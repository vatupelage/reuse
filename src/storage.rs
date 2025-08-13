use anyhow::Result;
use rusqlite::{Connection, params};
use crate::types::{SignatureRow, ScriptType, RecoveredKeyRow};
use std::collections::HashMap;

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn open(path: &str) -> Result<Self> {
        eprintln!("Opening database at: {}", path);
        
        let conn = Connection::open(path)?;
        eprintln!("Database connection established successfully");
        
        // Set SQLite pragmas for better performance
        conn.execute("PRAGMA journal_mode = WAL", [])?;
        conn.execute("PRAGMA synchronous = NORMAL", [])?;
        conn.execute("PRAGMA cache_size = 10000", [])?;
        conn.execute("PRAGMA temp_store = MEMORY", [])?;
        eprintln!("Database pragmas set successfully");
        
        let db = Self { conn };
        
        // Always try to initialize schema (CREATE TABLE IF NOT EXISTS will handle existing tables)
        eprintln!("Initializing database schema...");
        if let Err(e) = db.init_schema() {
            eprintln!("Warning: Failed to initialize database schema: {}", e);
            // Continue anyway, the database might already have the correct schema
        } else {
            eprintln!("Database schema initialized successfully");
        }
        
        Ok(db)
    }

    pub fn init_schema(&self) -> Result<()> {
        // Create tables and indexes in a single batch
        let schema_sql = r#"
            CREATE TABLE IF NOT EXISTS signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                block_height INTEGER NOT NULL,
                tx_hash TEXT NOT NULL,
                input_index INTEGER NOT NULL,
                r TEXT NOT NULL,
                s TEXT NOT NULL,
                z TEXT NOT NULL,
                pubkey TEXT NOT NULL,
                address TEXT NOT NULL,
                script_type TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE INDEX IF NOT EXISTS idx_signatures_r ON signatures(r);
            CREATE INDEX IF NOT EXISTS idx_signatures_block_height ON signatures(block_height);
            CREATE INDEX IF NOT EXISTS idx_signatures_tx_hash ON signatures(tx_hash);
            
            CREATE TABLE IF NOT EXISTS recovered_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                txid1 TEXT NOT NULL,
                txid2 TEXT NOT NULL,
                r TEXT NOT NULL,
                private_key TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE INDEX IF NOT EXISTS idx_recovered_keys_r ON recovered_keys(r);
            CREATE INDEX IF NOT EXISTS idx_recovered_keys_txid ON recovered_keys(txid1, txid2);
            
            CREATE TABLE IF NOT EXISTS script_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                script_type TEXT NOT NULL UNIQUE,
                count INTEGER NOT NULL DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        "#;
        
        // Execute schema creation with better error handling
        match self.conn.execute_batch(schema_sql) {
            Ok(_) => Ok(()),
            Err(e) => {
                eprintln!("Database schema creation failed: {}", e);
                eprintln!("Schema SQL: {}", schema_sql);
                Err(e.into())
            }
        }
    }

    pub fn insert_signatures_batch(&mut self, signatures: &[SignatureRow]) -> Result<()> {
        let tx = self.conn.transaction()?;

        let mut stmt = tx.prepare(
            "INSERT INTO signatures (block_height, tx_hash, input_index, r, s, z, pubkey, address, script_type, created_at) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)"
        )?;

        for sig in signatures {
            stmt.execute((
                sig.block_height,
                &sig.txid, // Using txid from SignatureRow as tx_hash
                0, // Default input_index since SignatureRow doesn't have it
                &sig.r,
                &sig.s,
                &sig.z,
                &sig.pubkey,
                &sig.address,
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
            
            // First try to update existing record
            let updated = self.conn.execute(
                "UPDATE script_analysis SET count = ?, updated_at = CURRENT_TIMESTAMP WHERE script_type = ?",
                (count, script_type_str),
            )?;
            
            // If no rows were updated, insert new record
            if updated == 0 {
                self.conn.execute(
                    "INSERT INTO script_analysis (script_type, count, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
                    (script_type_str, count),
                )?;
            }
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
            "SELECT tx_hash, block_height, address, pubkey, r, s, z, script_type 
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
                txid: row.get(0)?, // tx_hash maps to txid
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