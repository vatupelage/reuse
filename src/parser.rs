use anyhow::{anyhow, Result};
use bitcoin::{
    Block, Transaction, TxIn, Script, PublicKey, Address, Network,
    consensus::deserialize,
    sighash::{EcdsaSighashType, SighashCache}, // Correct import path
    blockdata::script::Instruction,             // Correct import path
};
use bitcoin_hashes::Hash;
use k256::ecdsa::Signature as K256Signature;
use tracing;
use crate::types::{SignatureRow, ScriptType, RawBlock, ParsedBlock}; // Added ParsedBlock
use crate::rpc::RpcClient;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use hex;
use tokio::time;
use std::time::Instant;

// Thread-safe rate limiter that can be shared across multiple threads
pub struct RateLimiter {
    max_per_second: u32,
    last_request: Arc<Mutex<Instant>>,
}

impl RateLimiter {
    pub fn new(max_per_second: u32) -> Self {
        Self {
            max_per_second,
            last_request: Arc::new(Mutex::new(Instant::now())),
        }
    }

    pub async fn wait_if_needed(&self) {
        let elapsed = {
            let last_request = self.last_request.lock().unwrap();
            last_request.elapsed()
        };
        
        let min_interval = time::Duration::from_millis(1000 / self.max_per_second as u64);
        if elapsed < min_interval {
            time::sleep(min_interval - elapsed).await;
        }
        
        // Update the last request time
        if let Ok(mut last_request) = self.last_request.lock() {
            *last_request = Instant::now();
        }
    }
}

pub async fn parse_block(
    raw_block: &RawBlock,
    rpc: &RpcClient,
    rate_limiter: &RateLimiter,
) -> Result<ParsedBlock> {
    let block: Block = deserialize(&hex::decode(&raw_block.hex)?)?;
    
    let mut signatures = Vec::new();
    let mut script_stats = HashMap::new();
    
    // First pass: collect all transaction IDs that we need for Z-value calculation
    let mut required_txids = HashSet::new();
    for tx in &block.txdata {
        for input in &tx.input {
            if !input.previous_output.is_null() {
                required_txids.insert(input.previous_output.txid);
            }
        }
    }
    
    // Fetch all required transactions using the rate limiter
    let mut tx_cache: HashMap<bitcoin::Txid, Transaction> = HashMap::new();
    
    for txid in &required_txids {
        // CRITICAL FIX: Apply rate limiting between EACH transaction fetch
        rate_limiter.wait_if_needed().await;
        
        match rpc.get_transaction(txid).await {
            Ok(tx) => {
                tx_cache.insert(*txid, tx);
            },
            Err(e) => {
                if e.to_string().contains("429") {
                    tracing::warn!("Rate limited for transaction {}, waiting 2 seconds...", txid);
                    time::sleep(time::Duration::from_millis(2000)).await;
                    // Try again after waiting
                    match rpc.get_transaction(txid).await {
                        Ok(tx) => {
                            tx_cache.insert(*txid, tx);
                        },
                        Err(e2) => {
                            tracing::warn!("Failed to fetch transaction {} after retry: {}", txid, e2);
                        }
                    }
                } else {
                    tracing::warn!("Failed to fetch transaction {}: {}", txid, e);
                }
            }
        }
    }
    
    tracing::info!("Fetched {}/{} required transactions for block {}", 
        tx_cache.len(), required_txids.len(), raw_block.height);
    
    if tx_cache.len() < required_txids.len() {
        tracing::warn!("Some transactions could not be fetched due to rate limiting. Proceeding with available data.");
    }
    
    // Second pass: process transactions and extract signatures
    for (tx_index, tx) in block.txdata.iter().enumerate() {
        for (input_index, input) in tx.input.iter().enumerate() {
            // Skip coinbase transaction input
            if tx_index == 0 && input_index == 0 {
                continue;
            }

            // Extract signature and sighash type
            if let Some((sig, sighash_type)) = extract_signature_from_input(input) {
                // Extract public key and address
                if let Some((pubkey, address, script_type)) = extract_pubkey_and_address(input)? {
                    // Calculate real message hash (z-value) using cached transaction
                    match calculate_message_hash_with_cache(
                        tx, 
                        input_index, 
                        input, 
                        sighash_type, 
                        &tx_cache
                    ) {
                        Ok(z_value) => {
                            // Extract r and s values from K256 signature
                            let sig_bytes = sig.to_bytes();
                            let r_bytes = &sig_bytes[..32];
                            let s_bytes = &sig_bytes[32..64];
                            
                            let sig_row = SignatureRow {
                                txid: tx.txid().to_string(),
                                block_height: raw_block.height,
                                input_index: input_index as u32,  // Added: Include actual input index
                                address: address.to_string(),
                                pubkey: hex::encode(pubkey.to_bytes()),
                                r: hex::encode(r_bytes),
                                s: hex::encode(s_bytes),
                                z: hex::encode(z_value),
                                script_type: script_type.clone(),
                            };
                            
                            signatures.push(sig_row);
                            
                            // Update script statistics
                            *script_stats.entry(script_type).or_insert(0) += 1;
                        },
                        Err(e) => {
                            // Skip this signature if we can't calculate Z-value
                            tracing::debug!("Skipping signature due to Z-value calculation failure: {}", e);
                            continue;
                        }
                    }
                }
            }
        }
    }

    Ok(ParsedBlock {
        height: raw_block.height,
        signatures,
        script_stats,
    })
}

// New function that uses cached transactions instead of individual RPC calls
fn calculate_message_hash_with_cache(
    tx: &Transaction, 
    input_index: usize, 
    input: &TxIn,
    sighash_type: u8,
    tx_cache: &HashMap<bitcoin::Txid, Transaction>
) -> Result<[u8; 32]> {
    // Try to get the previous transaction from cache
    if let Some(prev_tx) = tx_cache.get(&input.previous_output.txid) {
        let prev_output = prev_tx.output
            .get(input.previous_output.vout as usize)
            .ok_or_else(|| anyhow!("Invalid previous output index"))?;

        let sighash_type = EcdsaSighashType::from_consensus(sighash_type as u32);
        
        // Bitcoin 0.30 correct API - no need for Prevouts for these methods
        let mut sighash_cache = SighashCache::new(tx);
        
        // Determine script type from previous output
        let script_type = determine_script_type(&prev_output.script_pubkey);
        
        let hash = match script_type {
            ScriptType::P2PKH | ScriptType::P2PK => {
                // Legacy sighash - use correct Bitcoin 0.30 API
                let hash = sighash_cache.legacy_signature_hash(
                    input_index, 
                    &prev_output.script_pubkey, 
                    sighash_type.to_u32()
                )?;
                *hash.as_byte_array()
            },
            ScriptType::P2WPKH => {
                // SegWit v0 signature hash for P2WPKH
                let hash = sighash_cache.segwit_signature_hash(
                    input_index, 
                    &prev_output.script_pubkey, 
                    prev_output.value, 
                    sighash_type
                )?;
                *hash.as_byte_array()
            },
            ScriptType::P2WSH => {
                // SegWit v0 signature hash for P2WSH
                // CRITICAL FIX: Extract witness script from witness data, not from prev_output
                let witness_script = extract_witness_script_from_input(input)?;
                
                // FIXED: For P2WSH, we need to use the witness script directly, not its hash
                // The script code is the actual witness script for SegWit signature verification
                let hash = sighash_cache.segwit_signature_hash(
                    input_index, 
                    &witness_script,  // FIXED: Use witness script directly, not script_hash()
                    prev_output.value, 
                    sighash_type
                )?;
                *hash.as_byte_array()
            },
            ScriptType::P2SH => {
                // P2SH can contain legacy or SegWit scripts
                // CRITICAL FIX: Extract redeem script from scriptSig, not from prev_output
                let redeem_script = extract_redeem_script_from_input(input)?;
                
                // Determine the actual script type from the redeem script
                let actual_script_type = determine_script_type(&redeem_script);
                
                match actual_script_type {
                    ScriptType::P2WPKH => {
                        // P2SH-wrapped P2WPKH: need to derive proper script code
                        // Extract the public key hash from the redeem script
                        // P2WPKH redeem script format: OP_0 <20-byte-pubkey-hash>
                        if redeem_script.as_bytes().len() == 22 && 
                           redeem_script.as_bytes()[0] == 0x00 && 
                           redeem_script.as_bytes()[1] == 0x14 {
                            
                            let pubkey_hash = &redeem_script.as_bytes()[2..22];
                            // Create the script code for P2WPKH (OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG)
                            let script_code = bitcoin::blockdata::script::Builder::new()
                                .push_opcode(bitcoin::blockdata::opcodes::all::OP_DUP)
                                .push_opcode(bitcoin::blockdata::opcodes::all::OP_HASH160)
                                .push_slice(pubkey_hash.to_vec())
                                .push_opcode(bitcoin::blockdata::opcodes::all::OP_EQUALVERIFY)
                                .push_opcode(bitcoin::blockdata::opcodes::all::OP_CHECKSIG)
                                .into_script();
                            
                            let hash = sighash_cache.segwit_signature_hash(
                                input_index, 
                                &script_code,  // Use the derived script code
                                prev_output.value, 
                                sighash_type
                            )?;
                            *hash.as_byte_array()
                        } else {
                            return Err(anyhow!("Invalid P2WPKH redeem script format in P2SH"));
                        }
                    },
                    ScriptType::P2WSH => {
                        // P2SH-wrapped P2WSH: use redeem script directly
                        let hash = sighash_cache.segwit_signature_hash(
                            input_index, 
                            &redeem_script,  // Use redeem script directly
                            prev_output.value, 
                            sighash_type
                        )?;
                        *hash.as_byte_array()
                    },
                    _ => {
                        // P2SH-wrapped legacy: use legacy sighash
                        let hash = sighash_cache.legacy_signature_hash(
                            input_index, 
                            &redeem_script,  // Use redeem script, not prev_output script
                            sighash_type.to_u32()
                        )?;
                        *hash.as_byte_array()
                    }
                }
            },
            _ => {
                return Err(anyhow!("Unsupported script type for sighash calculation: {:?}", script_type));
            }
        };

        // Fixed: use correct method to get bytes from Sighash in Bitcoin 0.30
        Ok(hash)
    } else {
        // CRITICAL FIX: Instead of falling back to zero, return an error
        // This ensures we don't process signatures with invalid Z-values
        Err(anyhow!("Previous transaction {} not found in cache. Cannot calculate Z-value.", 
            input.previous_output.txid))
    }
}

fn determine_script_type(script: &Script) -> ScriptType {
    if script.is_p2pkh() {
        ScriptType::P2PKH
    } else if script.is_p2sh() {
        ScriptType::P2SH
    } else if script.is_v0_p2wpkh() {
        ScriptType::P2WPKH
    } else if script.is_v0_p2wsh() {
        ScriptType::P2WSH
    } else if script.is_p2pk() {
        ScriptType::P2PK
    } else {
        ScriptType::NonStandard
    }
}

fn extract_signature_from_input(input: &TxIn) -> Option<(K256Signature, u8)> {
    let mut candidates = Vec::new();
    
    // Try to parse signature from scriptSig pushes
    for instruction in input.script_sig.instructions() {
        if let Ok(Instruction::PushBytes(bytes)) = instruction {
            candidates.push(bytes.as_bytes());
        }
    }
    
    // For witness inputs, check witness data
    for witness_item in input.witness.iter() {
        candidates.push(witness_item);
    }

    for candidate in candidates {
        // Check if this looks like a signature (DER format)
        if candidate.len() > 1 {
            let sighash_byte = candidate.last().unwrap();
            let sighash_type = sighash_byte & 0x1f;
            
            // Strip sighash byte for signature parsing
            let sig_bytes = &candidate[..candidate.len() - 1];
            
            // Try parsing as DER signature
            if let Ok(sig) = K256Signature::from_der(sig_bytes) {
                return Some((sig, sighash_type));
            }
        }
    }
    None
}

fn extract_pubkey_and_address(input: &TxIn) -> Result<Option<(PublicKey, String, ScriptType)>> {
    // Check witness first (p2wpkh common case)
    for witness_item in input.witness.iter() {
        if is_likely_pubkey(witness_item) {
            if let Ok(pubkey) = PublicKey::from_slice(witness_item) {
                let address = pubkey_to_address(&pubkey);
                return Ok(Some((pubkey, address, ScriptType::P2WPKH)));
            }
        }
    }

    // Check scriptSig for P2PKH and P2SH-P2WPKH (nested SegWit)
    for instruction in input.script_sig.instructions() {
        if let Ok(Instruction::PushBytes(bytes)) = instruction {
            if is_likely_pubkey(bytes.as_bytes()) {
                if let Ok(pubkey) = PublicKey::from_slice(bytes.as_bytes()) {
                    let address = pubkey_to_address(&pubkey);
                    return Ok(Some((pubkey, address, ScriptType::P2PKH)));
                }
            }
            
            // ENHANCED: Check for P2SH-P2WPKH (nested SegWit)
            // The redeem script should be a P2WPKH script
            if bytes.as_bytes().len() == 22 && bytes.as_bytes()[0] == 0x00 && bytes.as_bytes()[1] == 0x14 {
                // This looks like a P2WPKH redeem script in P2SH
                // Extract the public key from witness data
                if input.witness.len() >= 2 {
                    let pubkey_bytes = &input.witness[1]; // Second witness item is usually the public key
                    if is_likely_pubkey(pubkey_bytes) {
                        if let Ok(pubkey) = PublicKey::from_slice(pubkey_bytes) {
                            let address = pubkey_to_address(&pubkey);
                            return Ok(Some((pubkey, address, ScriptType::P2SH))); // Mark as P2SH for proper handling
                        }
                    }
                }
            }
        }
    }

    Ok(None)
}

fn is_likely_pubkey(bytes: &[u8]) -> bool {
    // Check if bytes look like a public key
    if bytes.len() != 33 && bytes.len() != 65 {
        return false;
    }
    
    if bytes.len() == 33 {
        bytes[0] == 0x02 || bytes[0] == 0x03
    } else {
        bytes[0] == 0x04
    }
}

fn pubkey_to_address(pubkey: &PublicKey) -> String {
    // Convert to Bitcoin address (mainnet)
    let address = Address::p2pkh(pubkey, Network::Bitcoin);
    address.to_string()
}

fn extract_witness_script_from_input(input: &TxIn) -> Result<Script> {
    if input.witness.is_empty() {
        return Err(anyhow!("No witness data for P2WSH input"));
    }
    
    // The witness script is always the last item
    let witness_script_bytes = input.witness.last()
        .ok_or_else(|| anyhow!("Empty witness stack"))?;
    
    // Validate it looks like a script (basic check)
    if witness_script_bytes.is_empty() {
        return Err(anyhow!("Empty witness script"));
    }
    
    // Additional validation: check if it looks like a valid script
    if witness_script_bytes.len() < 2 {
        return Err(anyhow!("Witness script too short to be valid"));
    }
    
    Ok(Script::new(witness_script_bytes.to_vec()))
}

fn extract_redeem_script_from_input(input: &TxIn) -> Result<Script> {
    // For P2SH, the redeem script is in the scriptSig
    // Look for the last push operation in scriptSig
    let mut redeem_script = None;
    
    for instruction in input.script_sig.instructions() {
        if let Ok(Instruction::PushBytes(bytes)) = instruction {
            // The last push operation is typically the redeem script
            redeem_script = Some(Script::new(bytes.as_bytes().to_vec()));
        }
    }
    
    redeem_script.ok_or_else(|| anyhow!("No redeem script found in P2SH input"))
}