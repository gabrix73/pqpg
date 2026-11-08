use ed25519_dalek::{SigningKey, VerifyingKey};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("invalid key length or magic identifier")]
    InvalidFormat,
    #[error("cryptographic key parsing error")]
    ParsingError,
}

pub struct PublicKey {
    pub ed25519_pk: VerifyingKey,
    pub x25519_pk: X25519PublicKey,
    pub kem_pk_bytes: Vec<u8>,
}

pub struct PrivateKey {
    pub ed25519_sk: SigningKey,
    pub x25519_sk: StaticSecret,
    pub kem_sk_bytes: Zeroizing<Vec<u8>>,
}

impl PublicKey {
    pub const MAGIC: &'static [u8; 4] = b"PQPK";
    pub const VERSION: u8 = 0x01;

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + 1 + 32 + 32 + self.kem_pk_bytes.len());
        buf.extend_from_slice(Self::MAGIC);
        buf.push(Self::VERSION);
        buf.extend_from_slice(self.ed25519_pk.as_bytes());
        buf.extend_from_slice(self.x25519_pk.as_bytes());
        buf.extend_from_slice(&self.kem_pk_bytes);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, KeyError> {
        if data.len() < 4 + 1 + 32 + 32 + 1184 {
            return Err(KeyError::InvalidFormat);
        }
        if &data[0..4] != Self::MAGIC || data[4] != Self::VERSION {
            return Err(KeyError::InvalidFormat);
        }
        let ed_bytes: [u8; 32] = data[5..37].try_into().map_err(|_| KeyError::InvalidFormat)?;
        let ed25519_pk = VerifyingKey::from_bytes(&ed_bytes).map_err(|_| KeyError::ParsingError)?;

        let x_bytes: [u8; 32] = data[37..69].try_into().map_err(|_| KeyError::InvalidFormat)?;
        let x25519_pk = X25519PublicKey::from(x_bytes);

        let kem_pk_bytes = data[69..69 + 1184].to_vec();

        Ok(Self {
            ed25519_pk,
            x25519_pk,
            kem_pk_bytes,
        })
    }
}

impl PrivateKey {
    pub const MAGIC: &'static [u8; 4] = b"PQSK";
    pub const VERSION: u8 = 0x01;

    pub fn generate() -> (Self, PublicKey) {
        // 1. Ed25519 signing keypair
        let ed25519_sk = SigningKey::generate(&mut OsRng);
        let ed25519_pk = ed25519_sk.verifying_key();

        // 2. X25519 static DH keypair
        let x25519_sk = StaticSecret::random_from_rng(OsRng);
        let x25519_pk = X25519PublicKey::from(&x25519_sk);

        // 3. ML-KEM-768 keypair
        let (kem_dk, kem_ek) = MlKem768::generate(&mut OsRng);
        let kem_sk_bytes = Zeroizing::new(kem_dk.as_bytes().as_slice().to_vec());
        let _ = crate::mem::lock_slice(&kem_sk_bytes);
        let kem_pk_bytes = kem_ek.as_bytes().as_slice().to_vec();

        let priv_key = Self {
            ed25519_sk,
            x25519_sk,
            kem_sk_bytes,
        };

        let pub_key = PublicKey {
            ed25519_pk,
            x25519_pk,
            kem_pk_bytes,
        };

        (priv_key, pub_key)
    }

    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut buf = Zeroizing::new(Vec::with_capacity(4 + 1 + 32 + 32 + self.kem_sk_bytes.len()));
        buf.extend_from_slice(Self::MAGIC);
        buf.push(Self::VERSION);
        buf.extend_from_slice(self.ed25519_sk.as_bytes());
        buf.extend_from_slice(&self.x25519_sk.to_bytes());
        buf.extend_from_slice(&self.kem_sk_bytes);
        let _ = crate::mem::lock_slice(&buf);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, KeyError> {
        if data.len() < 4 + 1 + 32 + 32 + 2400 {
            return Err(KeyError::InvalidFormat);
        }
        if &data[0..4] != Self::MAGIC || data[4] != Self::VERSION {
            return Err(KeyError::InvalidFormat);
        }
        let ed_bytes: [u8; 32] = data[5..37].try_into().map_err(|_| KeyError::InvalidFormat)?;
        let ed25519_sk = SigningKey::from_bytes(&ed_bytes);

        let x_bytes: [u8; 32] = data[37..69].try_into().map_err(|_| KeyError::InvalidFormat)?;
        let x25519_sk = StaticSecret::from(x_bytes);

        let kem_sk_bytes = Zeroizing::new(data[69..69 + 2400].to_vec());
        let _ = crate::mem::lock_slice(&kem_sk_bytes);

        Ok(Self {
            ed25519_sk,
            x25519_sk,
            kem_sk_bytes,
        })
    }

    pub fn public_key(&self) -> PublicKey {
        let ed25519_pk = self.ed25519_sk.verifying_key();
        let x25519_pk = X25519PublicKey::from(&self.x25519_sk);

        // Derive KEM public key from secret key or store it
        // In ML-KEM, encapsulation key is embedded in decapsulation key bytes
        // In ML-KEM-768: decapsulation key is 2400 bytes, containing the 1184-byte encapsulation key
        // at offset 768..768+1184
        let kem_pk_bytes = self.kem_sk_bytes[768..768 + 1184].to_vec();

        PublicKey {
            ed25519_pk,
            x25519_pk,
            kem_pk_bytes,
        }
    }
}
