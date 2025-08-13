use anyhow::Result;
use rusqlite::{Connection, params};
use crate::types::{SignatureRow, RecoveredKeyRow, ScriptType};
use std::collections::HashMap;
use parking_lot::Mutex;

pub struct Database {
    conn: Mutex<Connection>,
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
        
        let db = Self { conn: Mutex::new(conn) };
        
        // Test the database connection with a simple query
        eprintln!("Testing database connection...");
        match db.conn.lock().query_row("SELECT 1", [], |_row| Ok(())) {
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
            eprintln!("Attempting to recreate database...");
            std::fs::remove_file(path)?;
            let conn = Connection::open(path)?;
            let db = Self { conn: Mutex::new(conn) };
            db.init_schema()?;
            return Ok(db);
        }
        
        Ok(db)
    }

    fn init_schema(&self) -> Result<()> {
        let schema_sql = r#"
            CREATE TABLE IF NOT EXISTS signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                txid TEXT NOT NULL,
                block_height INTEGER NOT NULL,
                input_index INTEGER NOT NULL,
                address TEXT NOT NULL,
                pubkey TEXT NOT NULL,
                r TEXT NOT NULL,
                s TEXT NOT NULL,
                z TEXT NOT NULL,
                script_type TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS recovered_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                txid1 TEXT NOT NULL,
                txid2 TEXT NOT NULL,
                r TEXT NOT NULL,
                private_key TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS script_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                script_type TEXT UNIQUE NOT NULL,
                count INTEGER NOT NULL DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS checkpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                block_height INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE INDEX IF NOT EXISTS idx_signatures_txid ON signatures(txid);
            CREATE INDEX IF NOT EXISTS idx_signatures_block_height ON signatures(block_height);
            CREATE INDEX IF NOT EXISTS idx_signatures_r ON signatures(r);
            CREATE INDEX IF NOT EXISTS idx_recovered_keys_r ON recovered_keys(r);
        "#;
        
        match self.conn.lock().execute_batch(schema_sql) {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into())
        }
    }

    pub fn insert_signatures_batch(&self, signatures: &[SignatureRow]) -> Result<()> {
        let mut tx = self.conn.lock().transaction()?;
        
        let mut stmt = tx.prepare(
            "INSERT INTO signatures (txid, block_height, input_index, address, pubkey, r, s, z, script_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )?;
        
        for sig in signatures {
            stmt.execute(params![
                sig.txid,
                sig.block_height,
                sig.input_index,
                sig.address,
                sig.pubkey,
                sig.r,
                sig.s,
                sig.z,
                sig.script_type.to_string()
            ])?;
        }
        
        tx.commit()?;
        Ok(())
    }

    pub fn upsert_script_stats_batch(&self, script_stats: &HashMap<ScriptType, u32>) -> Result<()> {
        for (script_type, count) in script_stats {
            let script_type_str = format!("{:?}", script_type);
            
            // Try to update existing record first
            let updated = self.conn.lock().execute(
                "UPDATE script_stats SET count = count + ?, updated_at = CURRENT_TIMESTAMP WHERE script_type = ?",
                params![count, script_type_str]
            )?;
            
            // If no rows were updated, insert new record
            if updated == 0 {
                self.conn.lock().execute(
                    "INSERT INTO script_stats (script_type, count) VALUES (?, ?)",
                    params![script_type_str, count]
                )?;
            }
        }
        Ok(())
    }

    pub fn insert_recovered_key(&self, recovered_key: &RecoveredKeyRow) -> Result<()> {
        self.conn.lock().execute(
            "INSERT INTO recovered_keys (txid1, txid2, r, private_key) VALUES (?, ?, ?, ?)",
            params![
                recovered_key.txid1,
                recovered_key.txid2,
                recovered_key.r,
                recovered_key.private_key
            ]
        )?;
        Ok(())
    }

    pub fn preload_recent_r_values(&self, limit: usize) -> Result<Vec<SignatureRow>> {
        let mut stmt = self.conn.lock().prepare(
            "SELECT txid, block_height, input_index, address, pubkey, r, s, z, script_type FROM signatures ORDER BY id DESC LIMIT ?"
        )?;
        
        let rows = stmt.query_map([limit], |row| {
            Ok(SignatureRow {
                txid: row.get(0)?,
                block_height: row.get(1)?,
                input_index: row.get(2)?,
                address: row.get(3)?,
                pubkey: row.get(4)?,
                r: row.get(5)?,
                s: row.get(6)?,
                z: row.get(7)?,
                script_type: row.get(8)?,
            })
        })?;
        
        let mut signatures = Vec::new();
        for row in rows {
            signatures.push(row?);
        }
        
        Ok(signatures)
    }

    pub fn get_signature_count(&self) -> Result<u64> {
        let count: u64 = self.conn.lock().query_row("SELECT COUNT(*) FROM signatures", [], |row| row.get(0))?;
        Ok(count)
    }

    pub fn get_recovered_key_count(&self) -> Result<u64> {
        let count: u64 = self.conn.lock().query_row("SELECT COUNT(*) FROM recovered_keys", [], |row| row.get(0))?;
        Ok(count)
    }
    
    pub fn save_checkpoint(&self, block_height: u32) -> Result<()> {
        self.conn.lock().execute(
            "INSERT INTO checkpoints (block_height) VALUES (?)",
            params![block_height]
        )?;
        Ok(())
    }
    
    pub fn get_last_checkpoint(&self) -> Result<Option<u32>> {
        let result = self.conn.lock().query_row(
            "SELECT block_height FROM checkpoints ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0)
        );
        
        match result {
            Ok(height) => Ok(Some(height)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into())
        }
    }
}