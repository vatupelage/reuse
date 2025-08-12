use anyhow::Result;
use k256::{Scalar, elliptic_curve::PrimeField};
use num_bigint::BigUint;
use num_traits::{One, Zero, ToPrimitive};
use num_integer::Integer;
use sha2::{Sha256, Digest};
use crate::types::{SignatureRow, RecoveredKeyRow};

pub fn attempt_recover_k_and_priv(sig1: &SignatureRow, sig2: &SignatureRow) -> Option<RecoveredKeyRow> {
    // Parse hex strings to BigUint
    let r = BigUint::from_str_radix(&sig1.r, 16).ok()?;
    let s1 = BigUint::from_str_radix(&sig1.s, 16).ok()?;
    let s2 = BigUint::from_str_radix(&sig2.s, 16).ok()?;
    let z1 = BigUint::from_str_radix(&sig1.z, 16).ok()?;
    let z2 = BigUint::from_str_radix(&sig2.z, 16).ok()?;

    // Convert to k256::Scalar for modular arithmetic
    let r_scalar = scalar_from_biguint(&r)?;
    let s1_scalar = scalar_from_biguint(&s1)?;
    let s2_scalar = scalar_from_biguint(&s2)?;
    let z1_scalar = scalar_from_biguint(&z1)?;
    let z2_scalar = scalar_from_biguint(&z2)?;

    // secp256k1 curve order n
    let n = Scalar::from_repr(
        k256::FieldBytes::from_slice(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
            0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
        ]).unwrap()
    ).unwrap();

    // k = (z1 - z2) * (s1 - s2)^-1 mod n
    let z_diff = z1_scalar.sub(&z2_scalar).normalize();
    let s_diff = s1_scalar.sub(&s2_scalar).normalize();
    let s_diff_inv = s_diff.invert().unwrap();
    let k = z_diff.mul(&s_diff_inv).normalize();

    // priv = (s1 * k - z1) * r^-1 mod n
    let r_inv = r_scalar.invert().unwrap();
    let sk1 = s1_scalar.mul(&k).normalize();
    let sk1_minus_z1 = sk1.sub(&z1_scalar).normalize();
    let private_key_scalar = sk1_minus_z1.mul(&r_inv).normalize();

    // Convert back to BigUint for WIF conversion
    let private_key_biguint = BigUint::from_bytes_be(&private_key_scalar.to_bytes().into());
    
    // Convert to WIF format
    let wif = bigint_to_wif(&private_key_biguint).ok()?;

    Some(RecoveredKeyRow {
        txid1: sig1.txid.clone(),
        txid2: sig2.txid.clone(),
        r: sig1.r.clone(),
        private_key: wif,
    })
}

fn scalar_from_biguint(bigint: &BigUint) -> Option<Scalar> {
    let bytes = bigint.to_bytes_be();
    if bytes.len() > 32 {
        return None; // Too large for secp256k1 scalar
    }
    
    let mut field_bytes = [0u8; 32];
    let start = 32 - bytes.len();
    field_bytes[start..].copy_from_slice(&bytes);
    
    Scalar::from_repr(k256::FieldBytes::from_slice(&field_bytes).unwrap()).ok()
}

fn bigint_to_wif(private_key: &BigUint) -> Result<String> {
    // Convert to 32-byte array
    let mut key_bytes = [0u8; 32];
    let key_vec = private_key.to_bytes_be();
    let start = 32 - key_vec.len();
    key_bytes[start..].copy_from_slice(&key_vec);
    
    // Add version byte (0x80 for mainnet)
    let mut extended_key = vec![0x80];
    extended_key.extend_from_slice(&key_bytes);
    
    // Add compression flag (0x01 for compressed public key)
    extended_key.push(0x01);
    
    // Double SHA256 for checksum
    let checksum = double_sha256(&extended_key);
    extended_key.extend_from_slice(&checksum[..4]);
    
    // Base58 encode
    let wif = base58_encode(&extended_key);
    Ok(wif)
}

fn double_sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let first_hash = hasher.finalize();
    
    let mut hasher = Sha256::new();
    hasher.update(first_hash);
    let second_hash = hasher.finalize();
    
    second_hash.to_vec()
}

fn base58_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    
    let mut num = BigUint::from_bytes_be(data);
    let mut result = Vec::new();
    
    while !num.is_zero() {
        let (quotient, remainder) = num.div_rem(&BigUint::from(58u32));
        num = quotient;
        result.push(ALPHABET[remainder.to_usize().unwrap()]);
    }
    
    // Add leading zeros
    for &byte in data {
        if byte == 0 {
            result.push(b'1');
        } else {
            break;
        }
    }
    
    result.reverse();
    String::from_utf8(result).unwrap()
}