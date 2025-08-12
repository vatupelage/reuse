use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub start_block: u64,
    pub end_block: u64,
    pub batch_size: usize,
    pub max_requests_per_block: usize,
    pub threads: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawBlock {
    pub height: u64,
    pub hash: String,
    pub raw_hex: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum ScriptType {
    P2PKH,
    P2WPKH,
    P2SH,
    P2WSH,
    NonStandard,
}

#[derive(Debug, Clone)]
pub struct ScriptStatsUpdate {
    pub script_type: ScriptType,
    pub count: u64,
}

#[derive(Debug, Clone)]
pub struct ParsedBlock {
    pub height: u64,
    pub tx_count: usize,
    pub sig_count: usize,
    pub signatures: Vec<SignatureRow>,
    pub script_stats: Vec<ScriptStatsUpdate>,
}

#[derive(Debug, Clone)]
pub struct SignatureRow {
    pub txid: String,
    pub block_height: u64,
    pub address: Option<String>,
    pub pubkey_hex: Option<String>,
    pub r_hex: String,
    pub s_hex: String,
    pub z_hex: String,
    pub script_type: String,
}

#[derive(Debug, Clone)]
pub struct RecoveredKeyRow {
    pub txid1: String,
    pub txid2: String,
    pub r_hex: String,
    pub private_key_wif: String,
}