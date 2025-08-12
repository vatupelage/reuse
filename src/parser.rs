use anyhow::{anyhow, Result};
use bitcoin::{
    consensus::encode::deserialize,
    Block, PublicKey, Script, Transaction, TxIn, TxOut,
    blockdata::script::Instruction,
    Address, Network,
    sighash::{SighashCache, EcdsaSighashType},  // Fixed: correct path for 0.30
};
use k256::ecdsa::Signature as K256Signature;
use std::collections::HashMap;

use crate::types::{ParsedBlock, RawBlock, SignatureRow, ScriptType};
use crate::rpc::RpcClient;

pub async fn parse_block(raw_block: &RawBlock, rpc: &RpcClient) -> Result<ParsedBlock> {
    let block: Block = deserialize(&hex::decode(&raw_block.hex)?)?;
    let mut signatures = Vec::new();
    let mut script_stats = std::collections::HashMap::new();

    for (tx_index, tx) in block.txdata.iter().enumerate() {
        for (input_index, input) in tx.input.iter().enumerate() {
            // Skip coinbase transactions
            if input.previous_output.is_null() {
                continue;
            }

            // Extract signature and sighash type
            if let Some((sig, sighash_type)) = extract_signature_from_input(input) {
                // Extract public key and address
                if let Some((pubkey, address, script_type)) = extract_pubkey_and_address(input)? {
                    // Calculate real message hash (z-value)
                    let z_value = calculate_message_hash(tx, input_index, input, sighash_type, rpc).await?;

                    let sig_row = SignatureRow {
                        txid: tx.txid().to_string(),
                        block_height: raw_block.height,
                        address: address.to_string(),
                        pubkey: hex::encode(pubkey.to_bytes()),
                        r: hex::encode(sig.r().to_bytes()),
                        s: hex::encode(sig.s().to_bytes()),
                        z: hex::encode(z_value),
                        script_type,
                    };
                    
                    signatures.push(sig_row);
                    
                    // Update script statistics
                    *script_stats.entry(script_type).or_insert(0) += 1;
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

async fn calculate_message_hash(
    tx: &Transaction, 
    input_index: usize, 
    input: &TxIn,
    sighash_type: u8,
    rpc: &RpcClient
) -> Result<[u8; 32]> {
    // Fetch the previous transaction to get the output being spent
    let prev_tx = rpc.get_transaction(&input.previous_output.txid).await?;
    let prev_output = prev_tx.output
        .get(input.previous_output.vout as usize)
        .ok_or_else(|| anyhow!("Invalid previous output index"))?;

    let sighash_type = EcdsaSighashType::from_consensus(sighash_type as u32);
    let mut cache = SighashCache::new(tx);
    
    // Determine script type from previous output
    let script_type = determine_script_type(&prev_output.script_pubkey);
    
    let hash = match script_type {
        ScriptType::P2PKH | ScriptType::P2PK => {
            // Legacy sighash - use correct Bitcoin 0.30 API
            cache.legacy_signature_hash(
                input_index, 
                &prev_output.script_pubkey, 
                sighash_type.to_u32()
            )?
        },
        ScriptType::P2WPKH => {
            // SegWit v0 signature hash for P2WPKH
            cache.segwit_signature_hash(
                input_index, 
                &prev_output.script_pubkey, 
                prev_output.value, 
                sighash_type
            )?
        },
        ScriptType::P2WSH => {
            // SegWit v0 signature hash for P2WSH
            cache.segwit_signature_hash(
                input_index, 
                &prev_output.script_pubkey, 
                prev_output.value, 
                sighash_type
            )?
        },
        ScriptType::P2SH => {
            // P2SH can contain legacy or SegWit scripts
            cache.legacy_signature_hash(
                input_index, 
                &prev_output.script_pubkey, 
                sighash_type.to_u32()
            )?
        },
        _ => {
            return Err(anyhow!("Unsupported script type for sighash calculation: {:?}", script_type));
        }
    };

    // Fixed: use correct method to get bytes from Sighash
    Ok(hash.to_byte_array())
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