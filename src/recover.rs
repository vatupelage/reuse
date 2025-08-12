use anyhow::{anyhow, Result};
use k256::Scalar;
use k256::ecdsa::Signature as K256Signature;
use k256::elliptic_curve::PrimeField;
use num_bigint::BigUint;
use num_traits::ToPrimitive;

use crate::types::{RecoveredKeyRow, SignatureRow};

pub fn attempt_recover_k_and_priv(sig1: &SignatureRow, sig2: &SignatureRow) -> Option<RecoveredKeyRow> {
    if sig1.r_hex != sig2.r_hex {
        return None;
    }

    // Parse scalars from hex (left-pad to 32 bytes)
    let r = hex32_to_scalar(&sig1.r_hex)?;
    let s1 = hex32_to_scalar(&sig1.s_hex)?;
    let s2 = hex32_to_scalar(&sig2.s_hex)?;
    let z1 = hex32_to_scalar(&sig1.z_hex)?;
    let z2 = hex32_to_scalar(&sig2.z_hex)?;

    // k = (z1 - z2) * (s1 - s2)^{-1} mod n
    let z_diff = z1 - z2;
    let s_diff = s1 - s2;
    if bool::from(s_diff.is_zero()) {
        return None;
    }
    let s_diff_inv = s_diff.invert();
    if !bool::from(s_diff_inv.is_some()) {
        return None;
    }
    let k = z_diff * s_diff_inv.unwrap();

    // priv = (s1 * k - z1) * r^{-1} mod n
    let r_inv = r.invert();
    if !bool::from(r_inv.is_some()) {
        return None;
    }
    let sk1 = s1 * k;
    let d = (sk1 - z1) * r_inv.unwrap();

    // Convert scalar d to WIF (mainnet, compressed)
    let wif = scalar_to_wif(&d).ok()?;

    Some(RecoveredKeyRow {
        txid1: sig1.txid.clone(),
        txid2: sig2.txid.clone(),
        r_hex: sig1.r_hex.clone(),
        private_key_wif: wif,
    })
}

fn hex32_to_scalar(hex_str: &str) -> Option<Scalar> {
    let mut buf = [0u8; 32];
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() > 32 { return None; }
    buf[32 - bytes.len()..].copy_from_slice(&bytes);
    let ct = Scalar::from_repr(buf.into());
    if bool::from(ct.is_some()) { Some(ct.unwrap()) } else { None }
}

fn scalar_to_wif(d: &Scalar) -> Result<String> {
    let priv_bytes = d.to_bytes();

    let mut wif_bytes = Vec::with_capacity(1 + 32 + 1 + 4);
    wif_bytes.push(0x80); // mainnet
    wif_bytes.extend_from_slice(priv_bytes.as_slice());
    wif_bytes.push(0x01); // compressed

    let checksum = double_sha256(&wif_bytes);
    wif_bytes.extend_from_slice(&checksum[..4]);

    Ok(base58_encode(&wif_bytes))
}

fn double_sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    let first = h.finalize();
    let mut h2 = Sha256::new();
    h2.update(first);
    h2.finalize().to_vec()
}

fn base58_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    let mut num = BigUint::from_bytes_be(data);
    let mut result = String::new();

    while num > BigUint::from(0u32) {
        let (q, r) = {
            use num_integer::Integer;
            num.div_rem(&BigUint::from(58u32))
        };
        result.push(ALPHABET[r.to_u32().unwrap() as usize] as char);
        num = q;
    }

    for &b in data {
        if b == 0 { result.push('1'); } else { break; }
    }

    result.chars().rev().collect()
}