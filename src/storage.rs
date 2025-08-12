use std::path::Path;

use anyhow::Result;
use rusqlite::{params, Connection, TransactionBehavior};

use crate::types::{RecoveredKeyRow, SignatureRow, ScriptStatsUpdate};

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", &"WAL")?;
        conn.pragma_update(None, "synchronous", &"NORMAL")?;
        conn.pragma_update(None, "temp_store", &"MEMORY")?;
        Ok(Self { conn })
    }

    pub fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS signatures (
                txid TEXT NOT NULL,
                block_height INTEGER NOT NULL,
                address TEXT,
                pubkey TEXT,
                r TEXT NOT NULL,
                s TEXT NOT NULL,
                z TEXT NOT NULL,
                script_type TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS recovered_keys (
                txid1 TEXT NOT NULL,
                txid2 TEXT NOT NULL,
                r TEXT NOT NULL,
                private_key TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS script_analysis (
                script_type TEXT PRIMARY KEY,
                count INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_signatures_r ON signatures(r);
            CREATE INDEX IF NOT EXISTS idx_signatures_pubkey ON signatures(pubkey);
            CREATE INDEX IF NOT EXISTS idx_signatures_address ON signatures(address);
            CREATE INDEX IF NOT EXISTS idx_signatures_txid ON signatures(txid);
            CREATE INDEX IF NOT EXISTS idx_signatures_r_pubkey ON signatures(r, pubkey);
            CREATE INDEX IF NOT EXISTS idx_signatures_address_script ON signatures(address, script_type);
        "#,
        )?;
        Ok(())
    }

    pub fn insert_signatures_batch(&mut self, sigs: &[SignatureRow]) -> Result<()> {
        if sigs.is_empty() { return Ok(()); }
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO signatures (txid, block_height, address, pubkey, r, s, z, script_type) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
            )?;
            for s in sigs {
                stmt.execute(params![
                    s.txid,
                    s.block_height as i64,
                    s.address,
                    s.pubkey_hex,
                    s.r_hex,
                    s.s_hex,
                    s.z_hex,
                    s.script_type,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn upsert_script_stats_batch(&mut self, stats: &[ScriptStatsUpdate]) -> Result<()> {
        if stats.is_empty() { return Ok(()); }
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO script_analysis (script_type, count) VALUES (?1, ?2)
                 ON CONFLICT(script_type) DO UPDATE SET count = script_analysis.count + excluded.count"
            )?;
            for s in stats {
                let key = format!("{:?}", s.script_type);
                stmt.execute(params![key, s.count as i64])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn insert_recovered_key(&mut self, row: &RecoveredKeyRow) -> Result<()> {
        self.conn.execute(
            "INSERT INTO recovered_keys (txid1, txid2, r, private_key) VALUES (?1, ?2, ?3, ?4)",
            params![row.txid1, row.txid2, row.r_hex, row.private_key_wif],
        )?;
        Ok(())
    }

    pub fn preload_recent_r_values(&self, limit: usize, cache: &mut crate::cache::RValueCache) -> Result<()> {
        let mut stmt = self
            .conn
            .prepare("SELECT txid, block_height, address, pubkey, r, s, z, script_type FROM signatures ORDER BY rowid DESC LIMIT ?1")?;
        let rows = stmt.query_map([limit as i64], |row| {
            Ok(SignatureRow {
                txid: row.get(0)?,
                block_height: row.get::<_, i64>(1)? as u64,
                address: row.get(2)?,
                pubkey_hex: row.get(3)?,
                r_hex: row.get(4)?,
                s_hex: row.get(5)?,
                z_hex: row.get(6)?,
                script_type: row.get(7)?,
            })
        })?;
        for r in rows {
            cache.insert_only(r?);
        }
        Ok(())
    }

    pub fn flush(&self) -> Result<()> { Ok(()) }

    pub fn save_report(&self, _stats: &crate::stats::RuntimeStats) -> Result<()> {
        // For brevity, skip persistence of separate JSON; caller can pipe logs.
        Ok(())
    }
}