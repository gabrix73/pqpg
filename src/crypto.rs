use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

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

pub const KEM_CT_LEN: usize = 1088;
pub const X25519_PK_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const HEADER_LEN: usize = 4 + 1 + KEM_CT_LEN + X25519_PK_LEN + NONCE_LEN; // 1137 bytes

/// Derives a 32-byte AEAD key from hybrid KEM and X25519 shared secrets
fn derive_hybrid_key(kem_ss: &[u8], x25519_ss: &[u8]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(kem_ss.len() + x25519_ss.len());
    ikm.extend_from_slice(kem_ss);
    ikm.extend_from_slice(x25519_ss);

    let hk = Hkdf::<Sha256>::new(Some(b"PQPG-HYBRID-KEM-V1"), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(b"chacha20-poly1305-key", &mut okm)
        .expect("32 bytes is valid length for HKDF");
    okm
}

/// Encrypts plaintext to recipient's hybrid public key (ML-KEM-768 + X25519)
pub fn encrypt_message(recipient: &PublicKey, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if recipient.kem_pk_bytes.len() != 1184 {
        return Err(CryptoError::InvalidFormat);
    }

    // 1. ML-KEM-768 encapsulation
    let ek_encoded = Encoded::<<MlKem768 as KemCore>::EncapsulationKey>::clone_from_slice(&recipient.kem_pk_bytes);
    let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(&ek_encoded);
    let (kem_ct, kem_ss) = ek.encapsulate(&mut OsRng).map_err(|_| CryptoError::KemError)?;

    // 2. Ephemeral X25519 Diffie-Hellman
    let ephemeral_x_sk = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_x_pk = X25519PublicKey::from(&ephemeral_x_sk);
    let x25519_ss = ephemeral_x_sk.diffie_hellman(&recipient.x25519_pk);

    // 3. Key derivation (hybrid KEM + DH)
    let aead_key = derive_hybrid_key(kem_ss.as_slice(), x25519_ss.as_bytes());

    // 4. ChaCha20-Poly1305 encryption
    let cipher = ChaCha20Poly1305::new((&aead_key).into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext_payload = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::AeadError)?;

    // 5. Assemble wire format
    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext_payload.len());
    out.extend_from_slice(MESSAGE_MAGIC);
    out.push(MESSAGE_VERSION);
    out.extend_from_slice(kem_ct.as_slice());
    out.extend_from_slice(ephemeral_x_pk.as_bytes());
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

    let kem_ct_bytes = &ciphertext[5..5 + KEM_CT_LEN];
    let x25519_pk_bytes: [u8; 32] = ciphertext[5 + KEM_CT_LEN..5 + KEM_CT_LEN + 32]
        .try_into()
        .map_err(|_| CryptoError::InvalidFormat)?;
    let nonce_bytes = &ciphertext[5 + KEM_CT_LEN + 32..HEADER_LEN];
    let payload = &ciphertext[HEADER_LEN..];

    // 1. ML-KEM-768 decapsulation
    let dk_encoded = Encoded::<<MlKem768 as KemCore>::DecapsulationKey>::clone_from_slice(&recipient_sk.kem_sk_bytes);
    let dk = <MlKem768 as KemCore>::DecapsulationKey::from_bytes(&dk_encoded);
    let ct_encoded = ml_kem::Ciphertext::<MlKem768>::clone_from_slice(kem_ct_bytes);
    let kem_ss = dk.decapsulate(&ct_encoded).map_err(|_| CryptoError::KemError)?;

    // 2. X25519 DH
    let ephemeral_x_pk = X25519PublicKey::from(x25519_pk_bytes);
    let x25519_ss = recipient_sk.x25519_sk.diffie_hellman(&ephemeral_x_pk);

    // 3. Key derivation
    let aead_key = derive_hybrid_key(kem_ss.as_slice(), x25519_ss.as_bytes());

    // 4. ChaCha20-Poly1305 decryption
    let cipher = ChaCha20Poly1305::new((&aead_key).into());
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
