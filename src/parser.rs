use anyhow::{anyhow, Result};
use bitcoin::{
    consensus::encode::deserialize,
    Block, PublicKey, Script, Transaction, TxIn, TxOut, Witness,
    util::sighash::{SighashCache, EcdsaSighashType},
    hashes::Hash,
};
use k256::ecdsa::Signature as K256Signature;
use std::collections::HashMap;

use crate::types::{ParsedBlock, RawBlock, ScriptStatsUpdate, SignatureRow, ScriptType};

pub fn parse_block(raw_block: &RawBlock) -> Result<ParsedBlock> {
    let block: Block = deserialize(&hex::decode(&raw_block.hex)?)?;
    let mut signatures = Vec::new();
    let mut script_stats = std::collections::HashMap::new();

    for (tx_index, tx) in block.txdata.iter().enumerate() {
        for (input_index, input) in tx.input.iter().enumerate() {
            // Extract signature and sighash type
            if let Some((sig, sighash_type)) = extract_signature_from_input(input) {
                // Extract public key and address
                if let Some((pubkey, address, script_type)) = extract_pubkey_and_address(input, &block, tx_index, input_index)? {
                    // Calculate real message hash (z-value)
                    let z_value = if let Some(prev_output) = get_previous_output(input, &block, tx_index, input_index)? {
                        calculate_message_hash(tx, input_index, &prev_output, sighash_type)?
                    } else {
                        // Fallback if we can't get previous output
                        [0u8; 32]
                    };

                    let sig_row = SignatureRow {
                        txid: tx.txid().to_string(),
                        block_height: raw_block.height,
                        address: address.to_string(),
                        pubkey: hex::encode(pubkey.to_bytes()),
                        r: hex::encode(sig.r.to_bytes()),
                        s: hex::encode(sig.s.to_bytes()),
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
        height: block.header.height,
        signatures,
        script_stats,
    })
}

fn calculate_message_hash(
    tx: &Transaction, 
    input_index: usize, 
    prev_output: &TxOut, 
    sighash_type: u8
) -> Result<[u8; 32]> {
    let sighash_type = EcdsaSighashType::from_consensus(sighash_type as u32);
    let mut cache = SighashCache::new(tx);
    
    // Determine script type from previous output
    let script_type = determine_script_type(&prev_output.script_pubkey);
    
    match script_type {
        ScriptType::P2PKH | ScriptType::P2SH => {
            Ok(cache.legacy_signature_hash(
                input_index, 
                &prev_output.script_pubkey, 
                sighash_type.to_u32()
            )?)
        },
        ScriptType::P2WPKH | ScriptType::P2WSH => {
            Ok(cache.segwit_signature_hash(
                input_index, 
                &prev_output.script_pubkey, 
                prev_output.value, 
                sighash_type
            )?)
        },
        _ => Err(anyhow!("Unsupported script type for sighash calculation: {:?}", script_type)),
    }
}

fn determine_script_type(script: &Script) -> ScriptType {
    if script.is_p2pkh() {
        ScriptType::P2PKH
    } else if script.is_p2sh() {
        ScriptType::P2SH
    } else if script.is_p2wpkh() {
        ScriptType::P2WPKH
    } else if script.is_p2wsh() {
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
    for opcode in input.script_sig.iter_pushdata() {
        if let Ok(bytes) = opcode {
            candidates.push(bytes);
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
            
            // Try strict DER first
            if let Ok(sig) = K256Signature::from_der(sig_bytes) {
                return Some((sig, sighash_type));
            }
            // Fallback to lax DER parsing
            if let Ok(sig) = K256Signature::from_der_lax(sig_bytes) {
                return Some((sig, sighash_type));
            }
        }
    }
    None
}

fn extract_pubkey_and_address(input: &TxIn, block: &Block, tx_index: usize, input_index: usize) -> Result<Option<(PublicKey, String, ScriptType)>> {
    // Check witness first (p2wpkh common case)
    for witness_item in input.witness.iter() {
        if is_likely_pubkey(witness_item) {
            if let Ok(pubkey) = PublicKey::from_slice(witness_item) {
                let address = pubkey_to_address(&pubkey);
                return Ok(Some((pubkey, address, ScriptType::P2WPKH)));
            }
        }
    }

    // Fallback: check scriptSig pushes
    for ins in input.script_sig.instructions() {
        if let Ok(Instruction::PushBytes(data)) = ins {
            let bytes = data.as_bytes();
            if is_likely_pubkey(bytes) {
                if let Ok(pubkey) = PublicKey::from_slice(bytes) {
                    let address = pubkey_to_address(&pubkey);
                    return Ok(Some((pubkey, address, ScriptType::P2PKH)));
                }
            }
        }
    }

    Ok(None)
}

fn is_likely_pubkey(bytes: &[u8]) -> bool {
    (bytes.len() == 33 && (bytes[0] == 0x02 || bytes[0] == 0x03)) ||
    (bytes.len() == 65 && bytes[0] == 0x04)
}

fn extract_pubkey_from_script(_script: &Script) -> Option<PublicKey> {
    None
}

fn find_signature_start(_script_bytes: &[u8]) -> Option<usize> { None }

fn pubkey_to_address(pubkey: &PublicKey) -> Option<String> {
    let address = Address::p2pkh(pubkey, Network::Bitcoin);
    Some(address.to_string())
}

fn classify_p2sh_script(_script: &Script) -> Option<ScriptType> { None }

// Helper function to get previous output (simplified - in practice you'd need UTXO access)
fn get_previous_output(
    _input: &TxIn, 
    _block: &Block, 
    _tx_index: usize, 
    _input_index: usize
) -> Result<Option<TxOut>> {
    // TODO: Implement proper UTXO lookup
    // For now, return None to use fallback z-value
    Ok(None)
}