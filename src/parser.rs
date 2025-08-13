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
use futures::future;
use hex;
use tokio::time;

pub async fn parse_block(
    raw_block: &RawBlock,
    rpc: &RpcClient,
) -> Result<ParsedBlock> {
    let block: Block = deserialize(&hex::decode(&raw_block.hex)?)?;
    
    let mut signatures = Vec::new();
    let mut script_stats = HashMap::new();
    
    // Build transaction cache for this block
    let mut tx_cache = HashMap::new();
    
    // First pass: collect all transaction IDs that we need for Z-value calculation
    let mut required_txids = HashSet::new();
    for tx in &block.txdata {
        for input in &tx.input {
            if !input.previous_output.is_null() {
                required_txids.insert(input.previous_output.txid);
            }
        }
    }
    
    // Fetch all required transactions with configurable rate limiting
    let mut tx_cache = HashMap::new();
    
    // Rate limiting configuration
    let batch_size = 3; // Process 3 transactions at a time
    let delay_between_requests = 200; // 200ms between individual requests
    let delay_between_batches = 1000; // 1 second between batches
    let retry_delay = 2000; // 2 seconds after rate limit
    
    let mut processed = 0;
    
    for txid in &required_txids {
        // Add delay between batches
        if processed > 0 && processed % batch_size == 0 {
            tracing::info!("Rate limiting: waiting {}ms between batches...", delay_between_batches);
            time::sleep(std::time::Duration::from_millis(delay_between_batches)).await;
        }
        
        match rpc.get_transaction(txid).await {
            Ok(tx) => {
                tx_cache.insert(*txid, tx);
                processed += 1;
            },
            Err(e) => {
                if e.to_string().contains("429") {
                    tracing::warn!("Rate limited for transaction {}, waiting {}ms...", txid, retry_delay);
                    time::sleep(std::time::Duration::from_millis(retry_delay)).await;
                    // Try again after waiting
                    match rpc.get_transaction(txid).await {
                        Ok(tx) => {
                            tx_cache.insert(*txid, tx);
                            processed += 1;
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
        
        // Small delay between individual requests
        time::sleep(std::time::Duration::from_millis(delay_between_requests)).await;
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
                let hash = sighash_cache.segwit_signature_hash(
                    input_index, 
                    &prev_output.script_pubkey, 
                    prev_output.value, 
                    sighash_type
                )?;
                *hash.as_byte_array()
            },
            ScriptType::P2SH => {
                // P2SH can contain legacy or SegWit scripts
                let hash = sighash_cache.legacy_signature_hash(
                    input_index, 
                    &prev_output.script_pubkey, 
                    sighash_type.to_u32()
                )?;
                *hash.as_byte_array()
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

    // Check scriptSig for P2PKH
    for instruction in input.script_sig.instructions() {
        if let Ok(Instruction::PushBytes(bytes)) = instruction {
            if is_likely_pubkey(bytes.as_bytes()) {
                if let Ok(pubkey) = PublicKey::from_slice(bytes.as_bytes()) {
                    let address = pubkey_to_address(&pubkey);
                    return Ok(Some((pubkey, address, ScriptType::P2PKH)));
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