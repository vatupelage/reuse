use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    pub start_block: u32,
    pub end_block: u32,
    pub threads: usize,
    pub db_path: String,
    pub batch_size: u32,
    pub rate_limit: u32,
    pub rpc_url: String,
    pub max_requests_per_block: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureRow {
    pub txid: String,
    pub block_height: u32,
    pub input_index: u32,  // Added: Track which input within the transaction
    pub address: String,
    pub pubkey: String,
    pub r: String,
    pub s: String,
    pub z: String,
    pub script_type: ScriptType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredKeyRow {
    pub txid1: String,
    pub txid2: String,
    pub r: String,
    pub private_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScriptType {
    P2PKH,
    P2SH,
    P2WPKH,
    P2WSH,
    P2PK,
    Multisig,
    NonStandard,
}

#[derive(Debug, Clone)]
pub struct RawBlock {
    pub height: u32,
    pub hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedBlock {
    pub height: u32,
    pub signatures: Vec<SignatureRow>,
    pub script_stats: HashMap<ScriptType, u64>,
}