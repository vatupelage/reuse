use anyhow::{anyhow, Result};
use bitcoin::{
    blockdata::script::{Instruction, Script},
    blockdata::transaction::TxIn,
    consensus::encode,
    Address, Network, PublicKey,
};
use bitcoin::secp256k1::ecdsa::Signature as SecpSignature;
use k256::ecdsa::Signature as K256Signature;
use std::collections::HashMap;

use crate::types::{ParsedBlock, RawBlock, ScriptStatsUpdate, SignatureRow, ScriptType};

pub fn parse_block(block: RawBlock) -> Result<ParsedBlock> {
    // Decode raw block hex
    let block_bytes = hex::decode(&block.raw_hex)
        .map_err(|e| anyhow!("failed to decode block hex: {e}"))?;
    
    let block_data: bitcoin::Block = encode::deserialize(&block_bytes)
        .map_err(|e| anyhow!("failed to deserialize block: {e}"))?;

    let mut signatures = Vec::new();
    let mut script_stats: HashMap<ScriptType, u64> = HashMap::new();
    let mut tx_count = 0;
    let mut sig_count = 0;

    // Process each transaction
    for tx in &block_data.txdata {
        tx_count += 1;
        
        // Process inputs (where signatures are)
        for input in tx.input.iter() {
            if let Some(sig) = extract_signature_from_input(input) {
                sig_count += 1;
                
                // Extract pubkey if available
                let (pubkey_hex, address, script_type) = extract_pubkey_and_address(input);

                // Convert secp256k1 DER signature into k256 signature to get r/s
                let der = sig.serialize_der();
                let ksig = match K256Signature::from_der(der.as_ref()) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let compact = ksig.to_bytes(); // 64 bytes: r||s
                let r_hex = hex::encode(&compact[..32]);
                let s_hex = hex::encode(&compact[32..]);
                
                // Create signature row
                let sig_row = SignatureRow {
                    txid: tx.txid().to_string(),
                    block_height: block.height,
                    address,
                    pubkey_hex,
                    r_hex,
                    s_hex,
                    z_hex: "0000000000000000000000000000000000000000000000000000000000000000".to_string(), // Placeholder
                    script_type: format!("{:?}", script_type),
                };
                
                signatures.push(sig_row);
                
                // Update script stats
                *script_stats.entry(script_type).or_insert(0) += 1;
            }
        }
    }

    // Convert script stats to updates
    let script_updates: Vec<ScriptStatsUpdate> = script_stats
        .into_iter()
        .map(|(script_type, count)| ScriptStatsUpdate { script_type, count })
        .collect();

    Ok(ParsedBlock {
        height: block.height,
        tx_count,
        sig_count,
        signatures,
        script_stats: script_updates,
    })
}

fn parse_der_signature_with_sighash(bytes: &[u8]) -> Option<SecpSignature> {
    if bytes.is_empty() {
        return None;
    }
    // Strip sighash type byte (last byte)
    let der_bytes = &bytes[..bytes.len().saturating_sub(1)];
    if der_bytes.first().copied() != Some(0x30) {
        return None;
    }
    if let Ok(sig) = SecpSignature::from_der(der_bytes) {
        return Some(sig);
    }
    // Try lax DER if strict fails
    if let Ok(sig) = SecpSignature::from_der_lax(der_bytes) {
        return Some(sig);
    }
    None
}

fn extract_signature_from_input(input: &TxIn) -> Option<SecpSignature> {
    // Try scriptSig pushes
    for ins in input.script_sig.instructions() {
        if let Ok(Instruction::PushBytes(data)) = ins {
            if let Some(sig) = parse_der_signature_with_sighash(data.as_bytes()) {
                return Some(sig);
            }
        }
    }

    // Try witness items (P2WPKH / P2WSH)
    for item in input.witness.iter() {
        if let Some(sig) = parse_der_signature_with_sighash(item) {
            return Some(sig);
        }
    }

    None
}

fn extract_pubkey_and_address(input: &TxIn) -> (Option<String>, Option<String>, ScriptType) {
    // Check witness first (p2wpkh common case)
    for item in input.witness.iter() {
        if is_likely_pubkey(item) {
            if let Ok(pubkey) = PublicKey::from_slice(item) {
                let address = pubkey_to_address(&pubkey);
                return (Some(hex::encode(pubkey.to_bytes())), address, ScriptType::P2WPKH);
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
                    return (Some(hex::encode(pubkey.to_bytes())), address, ScriptType::P2PKH);
                }
            }
        }
    }

    (None, None, ScriptType::NonStandard)
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