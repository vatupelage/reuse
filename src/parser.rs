use anyhow::{anyhow, Result};
use bitcoin::{
    consensus::encode::deserialize,
    Block, PublicKey, Script, Transaction, TxIn, TxOut,
    blockdata::script::Instruction,
    Address, Network,
    util::sighash::{Sighash, SighashCache, LegacySighash},
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
                if let Some((pubkey, address, script_type)) = extract_pubkey_and_address(input)? {
                    // Calculate real message hash (z-value) - for now use fallback
                    // TODO: Implement proper UTXO lookup for complete z-value calculation
                    let z_value = [0u8; 32]; // Placeholder until UTXO management is implemented

                    let sig_row = SignatureRow {
                        txid: tx.txid().to_string(),
                        block_height: raw_block.height, // Use raw_block height, not header.height
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
        height: raw_block.height, // Use raw_block height
        signatures,
        script_stats,
    })
}

fn extract_signature_from_input(input: &TxIn) -> Option<(K256Signature, u8)> {
    let mut candidates = Vec::new();
    
    // Try to parse signature from scriptSig pushes using correct Bitcoin 0.30 API
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
    // Check if bytes look like a public key (33 or 65 bytes, starting with 0x02, 0x03, or 0x04)
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

fn classify_p2sh_script(_script: &Script) -> Option<ScriptType> { 
    // TODO: Implement P2SH script classification
    None 
}