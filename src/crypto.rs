use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;
use rand::RngCore;
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use zeroize::Zeroizing;

use crate::keys::{PrivateKey, PublicKey};

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("KEM encapsulation/decapsulation failure")]
    KemError,
    #[error("AEAD encryption/decryption error")]
    AeadError,
    #[error("signature verification failed")]
    SignatureVerificationFailed,
    #[error("invalid message format or length")]
    InvalidFormat,
}

pub const MESSAGE_MAGIC: &[u8; 4] = b"PQPM";
pub const MESSAGE_VERSION: u8 = 0x01;

pub const X25519_PK_LEN: usize = 32;
pub const KEM_CT_LEN: usize = 1088;
pub const NONCE_LEN: usize = 12;
pub const HEADER_LEN: usize = 4 + 1 + X25519_PK_LEN + KEM_CT_LEN + NONCE_LEN; // 1137 bytes

/// Giacon, Heuer & Poettering KEM Combiner (HPQC Split-PRF Specification)
/// Domain-separated, length-prefixed split PRF combining X25519 and ML-KEM-768.
///
/// For each component i in 1..n:
///   key_i  := BLAKE2b-256(unkeyed)(ss_i)
///   hash_i := BLAKE2b-256(
///               key = key_i,
///               msg = "splitprf-v1" || u32be(n) ||
///                     u32be(len(cct_1)) || cct_1 ||
///                     ...
///                     u32be(len(cct_n)) || cct_n
///             )
/// return hash_1 XOR hash_2 XOR ... XOR hash_n
pub fn split_prf(parts: &[(&[u8], &[u8])]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    if parts.is_empty() {
        return Err(CryptoError::InvalidFormat);
    }

    let count = parts.len() as u32;
    let mut msg = b"splitprf-v1".to_vec();
    msg.extend_from_slice(&count.to_be_bytes());

    for (ss, ct) in parts {
        if ss.is_empty() || ct.is_empty() {
            return Err(CryptoError::InvalidFormat);
        }
        let ct_len = ct.len() as u32;
        msg.extend_from_slice(&ct_len.to_be_bytes());
        msg.extend_from_slice(ct);
    }

    let mut combined = Zeroizing::new([0u8; 32]);
    for (ss, _) in parts {
        let key_digest = blake2b_simd::Params::new()
            .hash_length(32)
            .hash(ss);
        let hash_i = blake2b_simd::Params::new()
            .hash_length(32)
            .key(key_digest.as_bytes())
            .hash(&msg);
        for (out_b, in_b) in combined.iter_mut().zip(hash_i.as_bytes().iter()) {
            *out_b ^= in_b;
        }
    }

    Ok(combined)
}

/// Encrypts plaintext to recipient's hybrid public key (X25519 + ML-KEM-768 via HPQC Split-PRF)
pub fn encrypt_message(recipient: &PublicKey, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if recipient.kem_pk_bytes.len() != 1184 {
        return Err(CryptoError::InvalidFormat);
    }

    // 1. Ephemeral X25519 Diffie-Hellman (HPQC Component 0)
    let ephemeral_x_sk = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_x_pk = X25519PublicKey::from(&ephemeral_x_sk);
    let x25519_ss = Zeroizing::new(ephemeral_x_sk.diffie_hellman(&recipient.x25519_pk));

    // 2. ML-KEM-768 encapsulation (HPQC Component 1)
    let ek_encoded = Encoded::<<MlKem768 as KemCore>::EncapsulationKey>::try_from(recipient.kem_pk_bytes.as_slice())
        .map_err(|_| CryptoError::InvalidFormat)?;
    let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(&ek_encoded);
    let (kem_ct, kem_ss) = ek.encapsulate(&mut OsRng).map_err(|_| CryptoError::KemError)?;

    // 3. HPQC Split-PRF key derivation combining X25519 and ML-KEM-768
    let aead_key = split_prf(&[
        (x25519_ss.as_bytes(), ephemeral_x_pk.as_bytes()),
        (kem_ss.as_slice(), kem_ct.as_slice()),
    ])?;

    // 4. ChaCha20-Poly1305 encryption
    let cipher = ChaCha20Poly1305::new(aead_key.as_slice().into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext_payload = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::AeadError)?;

    // 5. Assemble wire format: MAGIC(4) || VER(1) || X25519_PK(32) || KEM_CT(1088) || NONCE(12) || PAYLOAD
    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext_payload.len());
    out.extend_from_slice(MESSAGE_MAGIC);
    out.push(MESSAGE_VERSION);
    out.extend_from_slice(ephemeral_x_pk.as_bytes());
    out.extend_from_slice(kem_ct.as_slice());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext_payload);

    Ok(out)
}

/// Decrypts ciphertext with recipient's hybrid private key
pub fn decrypt_message(recipient_sk: &PrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < HEADER_LEN + 16 {
        return Err(CryptoError::InvalidFormat);
    }
    if &ciphertext[0..4] != MESSAGE_MAGIC || ciphertext[4] != MESSAGE_VERSION {
        return Err(CryptoError::InvalidFormat);
    }

    let x25519_pk_bytes: [u8; 32] = ciphertext[5..5 + X25519_PK_LEN]
        .try_into()
        .map_err(|_| CryptoError::InvalidFormat)?;
    let kem_ct_bytes = &ciphertext[5 + X25519_PK_LEN..5 + X25519_PK_LEN + KEM_CT_LEN];
    let nonce_bytes = &ciphertext[5 + X25519_PK_LEN + KEM_CT_LEN..HEADER_LEN];
    let payload = &ciphertext[HEADER_LEN..];

    // 1. Ephemeral X25519 DH
    let ephemeral_x_pk = X25519PublicKey::from(x25519_pk_bytes);
    let x25519_ss = Zeroizing::new(recipient_sk.x25519_sk.diffie_hellman(&ephemeral_x_pk));

    // 2. ML-KEM-768 decapsulation
    let dk_encoded = Encoded::<<MlKem768 as KemCore>::DecapsulationKey>::try_from(recipient_sk.kem_sk_bytes.as_slice())
        .map_err(|_| CryptoError::InvalidFormat)?;
    let dk = <MlKem768 as KemCore>::DecapsulationKey::from_bytes(&dk_encoded);
    let ct_encoded = ml_kem::Ciphertext::<MlKem768>::try_from(kem_ct_bytes)
        .map_err(|_| CryptoError::InvalidFormat)?;
    let kem_ss = dk.decapsulate(&ct_encoded).map_err(|_| CryptoError::KemError)?;

    // 3. HPQC Split-PRF key derivation
    let aead_key = split_prf(&[
        (x25519_ss.as_bytes(), &x25519_pk_bytes),
        (kem_ss.as_slice(), kem_ct_bytes),
    ])?;

    // 4. ChaCha20-Poly1305 decryption
    let cipher = ChaCha20Poly1305::new(aead_key.as_slice().into());
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::AeadError)?;

    Ok(plaintext)
}

/// Generates an Ed25519 detached digital signature
pub fn sign_data(signing_key: &SigningKey, data: &[u8]) -> Vec<u8> {
    let signature: Signature = signing_key.sign(data);
    signature.to_bytes().to_vec()
}

/// Verifies an Ed25519 digital signature
pub fn verify_data(verifying_key: &VerifyingKey, data: &[u8], sig_bytes: &[u8]) -> Result<(), CryptoError> {
    let sig = Signature::from_slice(sig_bytes).map_err(|_| CryptoError::SignatureVerificationFailed)?;
    verifying_key.verify(data, &sig).map_err(|_| CryptoError::SignatureVerificationFailed)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hpqc_split_prf_katzenpost_vector() {
        let ss0 = hex::decode("25adde77a065a96dbdd08e10c1cf9266b7117779e587aea674fb83fec5102def").unwrap();
        let ct0 = hex::decode("b2523b751dc1e1ccf7eb05b3de91a8b83a1a196bcf4d4e512d8d32aadfb4f15a").unwrap();
        let ss1 = hex::decode("6f293bc9d713969c9d1af5b15ce229f5b9dc76891418a9bcc3225c58651e9c56").unwrap();
        let ct1 = hex::decode(concat!(
            "3b8038cfd5628c6fe344b174f86b742cbc807365d6e5d2b28ebfda724f46d177",
            "af4bb86459cda4caa03d2a707debfd4cee220dfa6b92f334f6434ad64114f4b7",
            "6389c22b4eb97e98ef16c3e4f575294afb8c2d7e9f753027928163e5078facbb",
            "56b54daf735242210b32a34ef51359fea431321f1176a47cc72bc167fb3474f6",
            "6acdc5223d535c300da2374b0cba96053e260e516ca6d915fada06925c51f96b",
            "7cf3ddec9e817b0f7f8fe57c3dbf34ddb1186938a376f1cf03d4ccfbb4f12a11",
            "61ba4f8be7e47f8860fbaaf58878b93dc28de4253520d904ccff321c2258cb70",
            "7030fefab7fef3a9f76537046d9bcd6787dc94e2048841af5383909cebff012d",
            "6d6bf0c17368913357717289dee7f5edaae25bc61d0e22d04b674ed88dc31a72",
            "bf2566015fe4c5cafe8f247019a0f8bd306f2e681d5ec968ba78ecf606f66ebe",
            "24e223027603e06b7479248785183755785fdf1efeeba7528f5091e00b624e4b",
            "fb04999695952539876f5eca464adac0c0bb5a7dc5f1eaa9851131797670154c",
            "0f9084d902f76d3f96747f07c3a71f68cfd6e3537bb73c0c36da80d449e296a4",
            "217314b40d5289964fc1bd4a5de0dbfcb8e6d3a29b1e0d58d3a6b1d2abbac6a9",
            "82c22ddd3445318c7b93910d3755e781dd2de8d77745c114ac2a917254a1dfa5",
            "6b3890fe84e139a1c02fe3fe042a034b7bf4a01f3c16ad9a121e7770afac08e1",
            "51126a1ce96b880eb100e7f23d2de7da8f11bbf66366cd43a708986f95d66acf",
            "220666ae36317bca03f60da41ff6895662d8dc626248ba803dc17a3d2f926e9b",
            "3d1a582f763868fab58a769755f869d30a262f2c82479fd315f543a86684e169",
            "1ee1154f5908a6031f3e6d6061ee050099fa131bbe91064d306298e14cd71e14",
            "b2a06ec496e694e4861d1bc72192a4ce6f301c643c1cc69bc56c6e2a979ecb53",
            "b80cd860941ab98c6f24ebc218074b6dc4654d6c775437a202e2e118d2fdab89",
            "7e13eb60aff950e2b8da0f8e2841845ef1a8283d92c1e11d8718ac3077184780",
            "6ac0bff5c88d2fa0fa222c001c2984fa9c2a6aaa76348615276819892bd30558",
            "8cf5d38f9dcac7fe9372083ca5a9c899461705a23b9975ca295550ea27bd6617",
            "cbd525f75df202a49f6300a87c66731e9c2f78854a0ef3518183d85ffbc44f60",
            "8400752c80ef3ccaceb8a339726d12b4adf21055fda24817708165430b16ed49",
            "2e5455847ad1ab5fcf34a07b46a0d255a0466b9ff7d312a438efea244be71e0e",
            "930fbd072f13f69090d252817bdc4e93d10c5d5830dc12026af44e1c94276cc0",
            "480f40e3bf2156d20ebe55756e04b6e5237d0f89ac93b237c77f7b8ef2a1780d",
            "92999e227a0dda1b1ad69c2f5db9695219e12e5a5d492722cb3044eb096fc7fe",
            "051fe428648d2c712dab4e1498ef5ce394950c83d4fb6c8c8aaacbddaad637f5",
            "989dc4bbaff59f31c5bc62465ccd25f2d5f157527b61ea33b654c83a78956e82",
            "21608e9814eabdd535ef65a174bfe3e444b7c2a5d2714b38538257c0dbfe65f7"
        )).unwrap();

        let expected_combined_ss = "26a77928d3d2c9e90c5ccac2f9f771c3d749fbfe568be7bfbedaf2b97f168307";

        let combined = split_prf(&[
            (&ss0, &ct0),
            (&ss1, &ct1),
        ]).expect("split_prf failed");

        assert_eq!(hex::encode(*combined), expected_combined_ss);
    }

    #[test]
    fn test_hybrid_encryption_roundtrip() {
        let (sk, pk) = PrivateKey::generate();
        let message = b"Cypherpunks write code. Quantum computers will not break this.";

        let encrypted = encrypt_message(&pk, message).expect("encryption failed");
        assert_eq!(&encrypted[0..4], MESSAGE_MAGIC);

        let decrypted = decrypt_message(&sk, &encrypted).expect("decryption failed");
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_digital_signature_roundtrip() {
        let (sk, pk) = PrivateKey::generate();
        let document = b"Declaration of the Independence of Cyberspace";

        let sig = sign_data(&sk.ed25519_sk, document);
        assert_eq!(sig.len(), 64);

        assert!(verify_data(&pk.ed25519_pk, document, &sig).is_ok());

        // Tampered document must fail verification
        let tampered = b"Declaration of the Dependence of Cyberspace";
        assert!(verify_data(&pk.ed25519_pk, tampered, &sig).is_err());
    }
}
