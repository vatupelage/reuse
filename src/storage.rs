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
        
        // Check if database file already exists
        let db_exists = std::path::Path::new(path).exists();
        if db_exists {
            eprintln!("Database file already exists, checking compatibility...");
            
            // Check if we can read the file
            match std::fs::metadata(path) {
                Ok(metadata) => {
                    eprintln!("Database file size: {} bytes", metadata.len());
                    eprintln!("Database file permissions: {:?}", metadata.permissions());
                },
                Err(e) => {
                    eprintln!("Warning: Could not read database file metadata: {}", e);
                }
            }
        } else {
            eprintln!("Creating new database file...");
        }
        
        // Ensure the directory exists
        if let Some(parent) = std::path::Path::new(path).parent() {
            if !parent.exists() {
                eprintln!("Creating database directory: {:?}", parent);
                std::fs::create_dir_all(parent)?;
            }
            
            // Test if the directory is writable
            let test_file = parent.join(".test_write");
            match std::fs::write(&test_file, "test") {
                Ok(_) => {
                    std::fs::remove_file(&test_file).ok(); // Clean up test file
                    eprintln!("Database directory is writable");
                },
                Err(e) => {
                    eprintln!("Error: Database directory is not writable: {}", e);
                    return Err(anyhow::anyhow!("Database directory is not writable: {}", e));
                }
            }
        }
        
        // Try to open the database connection
        let conn = match Connection::open(path) {
            Ok(conn) => {
                eprintln!("Database connection established successfully");
                conn
            },
            Err(e) => {
                eprintln!("Failed to open database at {}: {}", path, e);
                return Err(e.into());
            }
        };
        
        // Set SQLite pragmas for better performance - use execute_batch to avoid "Execute returned results" error
        let pragma_sql = r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA cache_size = 10000;
            PRAGMA temp_store = MEMORY;
        "#;
        
        match conn.execute_batch(pragma_sql) {
            Ok(_) => eprintln!("Database pragmas set successfully"),
            Err(e) => {
                eprintln!("Warning: Failed to set database pragmas: {}", e);
                // Continue anyway, the database might work without these optimizations
            }
        }
        
        let db = Self { conn };
        
        // Test the database connection with a simple query
        eprintln!("Testing database connection...");
        match db.conn.query_row("SELECT 1", [], |_row| Ok(())) {
            Ok(_) => eprintln!("Database connection test successful"),
            Err(e) => {
                eprintln!("Warning: Database connection test failed: {}", e);
                // Continue anyway, might be a schema issue
            }
        }
        
        // Always try to initialize schema (CREATE TABLE IF NOT EXISTS will handle existing tables)
        eprintln!("Initializing database schema...");
        if let Err(e) = db.init_schema() {
            eprintln!("Warning: Failed to initialize database schema: {}", e);
            
            // If the database exists but schema initialization fails, try to recreate it
            if db_exists {
                eprintln!("Attempting to recreate database due to schema incompatibility...");
                drop(db); // Close the connection
                
                // Remove the old database file
                if let Err(remove_err) = std::fs::remove_file(path) {
                    eprintln!("Warning: Failed to remove old database: {}", remove_err);
                }
                
                // Try to open a new connection
                let conn = Connection::open(path)?;
                let db = Self { conn };
                
                // Initialize schema on the new database
                if let Err(e) = db.init_schema() {
                    eprintln!("Failed to initialize schema on new database: {}", e);
                    return Err(e.into());
                } else {
                    eprintln!("Database recreated and schema initialized successfully");
                }
                
                return Ok(db);
            }
            
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
            
            CREATE TABLE IF NOT EXISTS checkpoints (
                id INTEGER PRIMARY KEY,
                last_processed_block INTEGER NOT NULL,
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
                (count, script_type_str.clone()),
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
    
    pub fn save_checkpoint(&self, block_height: u32) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO checkpoints (id, last_processed_block, updated_at) VALUES (1, ?, CURRENT_TIMESTAMP)",
            params![block_height],
        )?;
        Ok(())
    }
    
    pub fn get_last_checkpoint(&self) -> Result<Option<u32>> {
        let result: Result<u32> = self.conn.query_row(
            "SELECT last_processed_block FROM checkpoints WHERE id = 1",
            [],
            |row| row.get(0)
        );
        
        match result {
            Ok(block_height) => Ok(Some(block_height)),
            Err(_) => Ok(None), // No checkpoint found
        }
    }
}